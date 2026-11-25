/** The TS types mirror the backend API contracts (src/hst/app/routes/). */

import type { ResultValue } from "../results/text";
import type { PaneView } from "../workspace/views";

export type Role = "viewer" | "operator" | "admin";

export interface Me {
  username: string;
  role: Role;
  /** The role's sorted permission set (src/hst/app/permissions.py). */
  permissions: string[];
  /** The account's stored palette preference; null when never chosen. */
  theme: string | null;
}

/** First-run setup. Same shape as a login, but it creates the account. */
export interface SetupRequest {
  username: string;
  password: string;
}

export interface SetupStatus {
  required: boolean;
  min_password_length: number;
}

export interface LoginRequest {
  username: string;
  password: string;
}

// --- /api/health -------------------------------------------------------------

export interface Health {
  path: boolean;
  neo4j: boolean;
  postgres: boolean;
  /** Ask-agent is enabled and has usable credentials. */
  agent?: boolean;
  /** The running build's version, shown at the bottom of the rail. */
  version?: string;
  /** The commit the running image was built from (HST_BUILD_REVISION). */
  revision?: string;
}

// --- /api/path -------------------------------------------------------------

export interface Hop {
  uid: string;
  kind: string;
  label: string;
  note: string;
  rank: number;
  /** The hop's stage on the packet's path (path.py's `Stage`). */
  stage?: string;
  lane: number;
  shared: boolean;
  /** The hop kind's declared schema layers (core/labels.py LabelSpec.layers). */
  layer?: string[];
  /** The hop's view tier (core/labels.py TIER_BY_KIND). */
  tier?: "physical" | "routing" | "policy" | "application";
  /** The hop draws as a gate (labels.py gate registry, less NatRule). */
  gate?: boolean;
  /** How many tunnels deep this hop sits: 0 (or absent) for the flow the user
   *  asked about, 1 for the encapsulated packet's own trip to the tunnel peer,
   *  2 for a carrier inside that carrier. The ribbon draws each level as a
   *  sub-lane under the lane's own row, between the ENCAP and DECAP stations. */
  overlay?: number;
  /** The Tunnel uid the hop rides in when `overlay` is set. */
  tunnel?: string;
  /** The hop belongs to a recursive next hop's own path: a device the route's
   *  next hop is reached through in the global table (the P routers under a
   *  VRF route). Drawn one sub-lane below the hop that named the next hop. */
  transport?: boolean;
}

export interface SdwanRuleEvaluation {
  position: number | null;
  name: string | null;
  /** Whether the rule is the first match of the flow: decided, or not decided
   *  on the match fields the trace cannot decide. */
  result: ResultValue;
  /** The match fields the trace cannot decide, or "" when the rule matches. */
  undecided: string;
  /** The route action: backhaul, gateway, direct or auto. */
  action: string;
  candidates: number;
}

/** Where a walk leaves the estate (docs: the trace answer of GET /api/path).
 *  `basis` says what makes the leg the estate's edge: a collected WAN link,
 *  the access client's default, or the operator's site zone "internet" of
 *  block `site_block`. */
export interface EstateExit {
  basis: "wan-link" | "access-client-default" | "site-zone";
  device_uid: string;
  device: string | null;
  interface_uid: string | null;
  interface: string | null;
  next_hop: string | null;
  wan_link_uid: string | null;
  wan_link: string | null;
  site_block: string | null;
}

/** An absent value means that the end is unknown. */
export type WalkReach = "destination" | "left_estate" | "split" | null;

export interface Leg {
  /** The trace drew the destination endpoint itself, so the lane ends on it. */
  delivered?: boolean;
  /** The rulebase whose decision decided this leg: the chip that carries the
   *  decision in the ribbon. */
  fw_uid?: string;
  /** The hop of the ACI contract deny that decided this leg. */
  blocking_uid?: string;
  /** Rulebases evaluated on upstream devices of a multi-hop path: each let the
   *  flow through, so each shows a permit. */
  fw_uids?: string[];
  /** Not blocked, but not decided either: the leg must not claim a permit. */
  indeterminate?: boolean;
  /** Destination NAT applied before a route lookup on this path, upstream device first. */
  dnat?: {
    to: string[];
    port: number | null;
    rule_uid: string;
    filter_view?: "original" | "translated";
  }[];
  /** Which destination the access policy that decided this leg was evaluated
   *  on when a destination NAT applied on the same device: "original" (the
   *  packet as it arrived, the Check Point order) or "translated" (the
   *  netfilter order). Absent when no translation applied, when the device has
   *  no access rulebase, or when the order could not be derived. */
  filter_view?: "original" | "translated";
  /** Source NAT applied at egress, one entry per translated source part.
   *  `mode` is present only on a load balancer's own rewrite, where it names
   *  which snat_mode resolved the address (snat_from, snip, automap). */
  snat?: { sources: string[]; to: string; rule_uid: string; mode?: string }[];
  /** The encapsulated packet's trip to the tunnel peer. */
  carrier?: {
    endpoint: string;
    port?: number | null;
    proto?: string;
    src?: string | null;
    cidr?: string;
    egress?: string | null;
    firewall?: string;
    snat?: string;
    /** the tracer's prose on the carrier */
    detail: string;
    /** whether the carrier is forwarded */
    result: ResultValue;
    /** The carrier network the WAN link is bought from, when one is recorded. */
    provider?: string;
    /** The carrier's arrival on the device that holds the tunnel's far
     *  address, before the inner flow was decapsulated there. */
    arrival?: { detail: string; result: ResultValue; blocked?: boolean; indeterminate?: boolean; terminus?: string };
    /** The carrier leaves the estate here. */
    left_estate?: EstateExit;
  };
  /** This leg is one of an SD-WAN forwarding boundary's candidate paths: the
   *  edge has no route table and dynamic path selection is not in the
   *  snapshot, so the drawn candidates are not a decision. */
  candidate_set?: boolean;
  /** The business policy rules the SD-WAN boundary evaluated for this leg,
   *  in position order. Absent when the boundary did not read the policy. */
  sdwan_rules?: SdwanRuleEvaluation[];
  /** The devices a recursive next hop was reached through, in order. */
  transport?: string[];
  /** The source candidate that this leg's forward simulation rests on. */
  interpretation?: { src_ip: string; anchor: string | null; display: string };
  /** The path left the twin at this leg's device. */
  boundary?: boolean;
  /** This leg is the estate's edge. */
  left_estate?: EstateExit;
  /** The destination is one of the device's own interface addresses. */
  router_local?: boolean;
  /** The (protocol, port) rectangle that this leg answers for. */
  service?: { proto: string[]; ports: [number, number][] };
  lane: number;
  sources: string[];
  cidr: string | null;
  egress: string | null;
  next_hop: string | null;
  blocked: boolean;
  table: string | null;
  src_label: string;
  firewall?: string;
  /** the tracer's prose on the leg */
  detail: string;
  /** whether the device forwards the flow at this hop */
  result: ResultValue;
}

/** The collection run a pinned answer was computed from. `degraded` and the
 *  carried, failed and partial source lists come from the run's CycleRun meta
 *  node; null when nothing was pinned or the meta node is absent. */
export interface CycleRunStatus {
  snapshot: string;
  created: string | null;
  degraded: boolean;
  sources_carried: string[];
  sources_failed: string[];
  sources_partial: string[];
  /** Sources that an operator stopped mid-cycle. */
  sources_cancelled: string[];
  /** The per-device freshness from the run's manifest (FEAT-05). */
  freshness?: RunFreshness;
}

export interface DeviceFreshness {
  source: string;
  host: string;
  /** "collected", "partial", "unchanged", "failed" or "carried". */
  outcome: string;
  carried: boolean;
  carried_reason: string | null;
  last_seen: number | null;
  tables: Record<string, TableFreshness>;
}

export interface RunFreshness {
  devices: DeviceFreshness[];
  truncated: boolean;
  approximate: boolean;
}

export interface PathResponse {
  mtu?: MtuResult;
  /** the tracer's prose on the whole walk */
  detail: string;
  /** whether the flow is forwarded on all candidate paths */
  result: ResultValue;
  notes: string[];
  /** The subset of `notes` where the engine could not prove something. */
  warnings?: string[];
  hops: Hop[];
  legs: Leg[];
  /** Any leg could not be decided by a gate the engine evaluates. */
  indeterminate?: boolean;
  /** Any leg left the twin (see Leg.boundary). */
  boundary?: boolean;
  /** The distinct estate exits of the walk's legs. */
  left_estate?: EstateExit[];
  reach?: WalkReach;
  run?: CycleRunStatus | null;
}

// --- /api/path (time travel: snapshot / snapshot_b) -------------------------

/** `snapshot` is the run id that this side was pinned to. */
export interface PathCompareSide {
  snapshot: string;
  result: PathResponse;
}

/** GET /api/path's shape when both `snapshot` and `snapshot_b` are given. */
export interface PathCompareResponse {
  a: PathCompareSide;
  b: PathCompareSide;
}

// --- /api/path?reply=true (the reply path) ----------------------------------

/** One reply lane of a forward trace that fanned out: the
 *  reply derived for a single forward leg, in the same PathResponse shape a
 *  one-leg reply carries. `forward_leg` is that leg's index in
 *  `forward.legs`, `src_label` the source partition it answers for (the lane
 *  label), `destinations` the reply's own destination set, and `asymmetric`
 *  the comparison for this forward-and-reply pair alone. */
export interface ReplyLane extends PathResponse {
  forward_leg: number;
  src_label: string;
  destinations: string[];
  asymmetric: boolean;
}

/** GET /api/path's shape when `reply=true` is given. */
export interface BidirectionalPathResponse {
  forward: PathResponse;
  /** One PathResponse when the forward trace produced one leg, else one ReplyLane per forward leg. */
  reply: (PathResponse & { destinations?: string[] }) | ReplyLane[];
  asymmetric: boolean;
  notes: string[];
  run?: CycleRunStatus | null;
}

// --- /api/queries ------------------------------------------------------------

export interface QueryParam {
  name: string;
  label: string;
  placeholder?: string;
  /** The label and property whose values the form suggests (GET /api/explore/values). */
  picker?: { label: string; property: string };
  /** May be left empty: the query then answers for every value (the device filter: any device). */
  optional?: boolean;
}

export interface CannedQuery {
  key: string;
  group: string;
  /** The rail label fits the 216px rail on one line. */
  title: string;
  /** What the query traverses. */
  description?: string;
  cypher: string;
  params?: QueryParam[];
  /** The name the rail and the palette show for `group`. */
  group_title?: string;
  /** A section inside the group, for example ZPA and ZIA in zscaler. */
  section?: string;
  /** More words the palette matches, beside the title and the group. */
  keywords?: string[];
}

export interface QueryCatalog {
  queries: CannedQuery[];
  /** The vendor products that hold data in the pinned run. Left out when the
   *  server does not know; every vendor view then stays listed. */
  products?: string[];
}

/** A vendor view is listed unless the catalog says its product holds no data. */
export function viewHasData(view: string, catalog: QueryCatalog | undefined): boolean {
  const product = view === "sdwan" || view === "equinix" ? view : null;
  if (product === null || !catalog?.products) return true;
  return catalog.products.includes(product);
}

// --- /api/sites --------------------------------------------------------------

/** Geography: where kit physically sits. Not a routing namespace (that is a
 *  VRF's L3 domain) and not a bridging domain (that is `l2scope`). */
export interface Site {
  code: string;
  name: string;
  location: string;
  /** Every device the placement rule puts here, however it got here. */
  device_count: number;
  /** What deleting this site would release. */
  group_count?: number;
  location_count?: number;
  placed_count?: number;
  params?: {
    routing_scope?: string | null;
    l2fabric?: string | null;
    /** the site's place on the site map; both or neither */
    lat?: number | null;
    lon?: number | null;
  };
}

export interface SitesResponse {
  sites: Site[];
}

export interface SiteDevice {
  uid: string;
  hostname: string | null;
  platform: string | null;
  /** Where the device sits. A group device follows its group; a controller
   * device follows its hand placement, then its bound location. Null when
   * nothing places it. */
  site?: string | null;
  /** A person put it there. Only a controller device can be. */
  hand_placed?: boolean;
  /** Whether this device may be placed by hand at all. False for a group
   * device, whose site is its group's, and for one no collection has seen. */
  can_place?: boolean;
  /** The site currently on the graph's LOCATED_IN edge. */
  graph_site?: string | null;
  /** The group or orchestrator this device was collected through. */
  source?: string;
  /** The place its source reports, in that system's own terms. Empty when the
   * source reports none; the display name is only shown, never matched. */
  location_id?: string;
  location_name?: string;
}

/** A place an orchestrator names, and the site an operator bound it to. A null
 * site means unplaced: its devices carry no LOCATED_IN edge. */
export interface ReportedLocation {
  source: string;
  location_id: string;
  name: string;
  site: string | null;
  device_count: number;
}

export interface ReportedLocationsResponse {
  locations: ReportedLocation[];
}

export interface SiteDevicesResponse {
  devices: SiteDevice[];
}

/** What deleting a site let go of. */
export interface SiteRelease {
  groups: string[];
  locations: { source: string; location_id: string }[];
  devices: string[];
}

/** A named block of a site. A device uid is in at most one block of its site. */
export interface SiteBlock {
  name: string;
  zone: "internal" | "external" | "internet" | null;
  devices: string[];
}

// --- Ask-AI agent ----------------------------------------------------------

/** A credential field a provider needs. Values are write-only: the server
 *  accepts them but never returns them. */
export interface AiCredentialField {
  name: string;
  label: string;
  secret: boolean;
  placeholder?: string;
  /** How the form renders it. "checkbox" is stored as "true" or absent;
   *  "textarea" carries PEM material. Absent means a text input. */
  kind?: "text" | "textarea" | "checkbox";
  required?: boolean;
  help?: string;
}

export interface AiProvider {
  id: string;
  label: string;
  credentials: AiCredentialField[];
  /** The non-secret settings that the provider needs. */
  options?: AiCredentialField[];
  /** Suggested model ids. */
  models: string[];
  /** The field applies to the Anthropic family only. */
  supports_effort: boolean;
}

/** One fixed layer of the conversational prompt. Only an admin's site
 *  instructions are editable; these layers are shown read-only. */
export interface AiPromptLayer {
  id: string;
  label: string;
  text: string;
}

export interface AiProviders {
  providers: AiProvider[];
  /** The fixed prompt layers around the site instructions, in assembly order. */
  prompt_layers: AiPromptLayer[];
}

export interface AiSettings {
  enabled: boolean;
  provider: string;
  model: string;
  effort: string;
  /** The site instructions. In `replace` mode, the whole prompt of the
   *  conversational surfaces in place of the fixed layers. */
  system_prompt: string;
  /** `append` adds the site instructions to the fixed layers. */
  prompt_mode?: "append" | "replace";
  options?: Record<string, string>;
  /** Which credential fields have a value on file. */
  stored_credentials?: string[];
  /** True when everything the chosen provider needs is present. */
  configured?: boolean;
  /** True when the stored credentials blob does not decrypt under the current key. */
  secrets_unreadable?: boolean;
  updated_at?: string;
}

// --- /api/settings/retention -------------------------------------------------

/** The keep intervals for every store that grows on its own. The server sends
 *  the values in force: what is stored, or the environment's defaults where
 *  nothing is. */
export interface RetentionSettings {
  /** Collection cycles of graph history kept; at least 1. */
  cycle_keep_runs: number;
  /** Device and refresh runs of graph history kept beside the cycles; 0 keeps
   *  none beyond the current run. */
  cycle_keep_device_runs: number;
  /** Age in days past which login records are deleted; 0 keeps everything. */
  login_event_retention_days: number;
  /** Age in days past which Cypher records are deleted; 0 keeps everything. */
  cypher_event_retention_days: number;
  /** Age in days past which finished maintenance jobs are deleted; 0 keeps
   *  everything. */
  job_history_retention_days: number;
  /** Age in days past which an AI conversation with no new message is deleted;
   *  0 keeps everything, ephemeral conversations included. */
  ai_conversation_retention_days: number;
  /** Age in days past which an AI tool result is compacted to its digest and
   *  summary; 0 keeps every result. */
  ai_step_result_days: number;
  /** Age in days past which AI events are deleted; 0 keeps everything. */
  ai_event_retention_days: number;
  /** When these were last saved; null while the environment alone is in charge. */
  updated_at: string | null;
}

/** PATCH body: every field optional, and an omitted field keeps tracking
 *  whatever it tracked before. */
export type RetentionPatch = Partial<Omit<RetentionSettings, "updated_at">>;

/** DELETE /api/users/{id}/sessions: how many sessions and personal access
 * tokens the revoke ended. */
export interface RevokedSessions {
  revoked: number;
  revoked_tokens?: number;
}

// --- /api/access-tokens and /api/settings/mcp --------------------------------

/** The scope of a personal access token, chosen at creation and never changed. */
export type TokenScope = "read" | "read-write";

/** One personal access token, as listed. The token text is never listed. */
export interface AccessToken {
  id: number;
  name: string;
  scope: TokenScope;
  created_at: string;
  expires_at: string;
  /** Null until the token first authenticates. */
  last_used_at: string | null;
  expired: boolean;
}

/** GET /api/access-tokens: the caller's tokens, newest first. */
export interface AccessTokenList {
  tokens: AccessToken[];
  /** Whether an admin enabled the MCP HTTP transport at /api/mcp. */
  mcp_http_enabled: boolean;
}

/** POST /api/access-tokens body. The server defaults `scope` to "read" and
 *  `expires_in_days` to 90. */
export interface AccessTokenCreate {
  name: string;
  scope?: TokenScope;
  expires_in_days?: number;
}

/** POST /api/access-tokens answer: the new token, with its text shown once. */
export interface AccessTokenCreated extends AccessToken {
  token: string;
}

/** GET and PUT /api/settings/mcp. */
export interface McpSettings {
  mcp_http_enabled: boolean;
}

/** One text turn of a HST AI transcript. */
export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

export interface AgentStep {
  name: string;
  arguments: Record<string, unknown>;
  result: string;
  is_error: boolean;
}

/** What the pinned snapshot records about one entity the question named. */
export interface AgentContextEntry {
  kind: "address" | "device";
  /** The address, or the device uid the named hostname resolved to. */
  subject: string;
  tool: "inventory_resolve" | "impact_assess" | "resolve_address" | "assess_impact";
  result: unknown;
}

// --- conversations: /api/ai/conversations, /api/ai/messages ------------------
// (src/hst/app/routes/ai_conversations.py)

/** The surfaces a client creates conversations on. */
export type ConversationSurface = "drawer" | "changesim" | "assessment_qa";

/** One step of a message in GET /api/ai/conversations/{id}. The full result
 *  is read through the message or GET /api/ai/steps/{id}. */
export interface ConversationStepMeta {
  id: string;
  /** The conversation-wide label, such as `s1`. */
  step: string;
  tool: string;
  tool_version: string | null;
  arguments: Record<string, unknown>;
  is_error: boolean;
  result_chars: number | null;
  result_summary: string | null;
  /** Compaction removed the full result; the summary remains. */
  compacted: boolean;
  started_at: string | null;
  elapsed_ms: number | null;
}

/** pending and running are the states of a turn in progress. */
export type ConversationMessageStatus =
  | "pending"
  | "running"
  | "done"
  | "error"
  | "cancelled"
  | "interrupted";

export interface ConversationMessage {
  id: string;
  seq: number;
  role: "user" | "assistant";
  status: ConversationMessageStatus;
  content: string;
  /** The page context sent with a question. */
  context: PageContext | null;
  /** The answer envelope of an answer stored with one, with the poll fields
   *  under `payload`. */
  envelope: Partial<AnswerEnvelope> | null;
  error: string | null;
  snapshot: string | null;
  created_at: string | null;
  finished_at: string | null;
  steps: ConversationStepMeta[];
}

/** POST /api/ai/conversations answers the fields without `messages`. */
/** A reference between a conversation and another object (`ai_links`).
 *  `direction` is `from` when the chat was opened from the object and `to`
 *  when the chat created the object or handed off to it. */
export interface ConversationLink {
  kind: string;
  ref_id: string;
  ref_revision: number | null;
  direction: "from" | "to";
  message_id: string | null;
  step_id: string | null;
  created_at: string | null;
}

export interface AiConversation {
  id: string;
  surface: string;
  title: string;
  pin: string | null;
  pin_mode: string;
  message_count: number;
  created_at: string | null;
  last_message_at: string | null;
  messages?: ConversationMessage[];
  /** The conversation read (GET /api/ai/conversations/{id}) carries them. */
  links?: ConversationLink[];
  /** The list (GET /api/ai/conversations): the run of the newest answer that
   *  names one. The list also gives an untitled conversation the start of
   *  its first question as `title`. */
  last_run?: string | null;
}

/** POST /api/ai/conversations/{id}/messages starts a turn and answers its
 *  assistant message id; GET /api/ai/messages/{id} is polled for the turn. */
export interface TurnStarted {
  message_id: string;
}

export interface TurnStep extends AgentStep {
  id: string;
  step: string;
}

/** GET /api/ai/messages/{id}. While the turn runs, `steps` holds the steps
 *  recorded so far. */
export interface TurnPoll {
  status: "running" | "done" | "error";
  /** The message status behind `status`. */
  state: ConversationMessageStatus;
  /** Why a turn ended without an answer. */
  detail?: string;
  message_id: string;
  conversation_id: string;
  answer: string;
  declined: boolean;
  steps: TurnStep[];
  /** The page context stored with the question. */
  context: PageContext | null;
  snapshot: string | null;
  /** The entity context of a question sent with `include_context`. */
  context_entries: AgentContextEntry[];
  page_context: string | null;
  prompt_hash: string | null;
  /** The answer envelope of a finished answer, without `payload`; null for
   *  an answer stored without one. */
  envelope?: AnswerEnvelope | null;
}

// --- answer envelope: strata/ai/answer-envelope/v2 ----------------------------
// (src/hst/app/ai/envelope.py)

/** The poll fields a turn stores beside its answer envelope. */
export interface TurnPayload {
  declined?: boolean;
  context_entries?: AgentContextEntry[];
}

/** How one claim of an answer is tied to the tool steps. */
export type CitationStatus =
  | "cited"
  | "prior-turn"
  | "cross-snapshot"
  | "citation-invalid"
  | "matched"
  | "process"
  | "uncited";

/** A record of a step result that holds what a claim names: the JSON pointer
 *  into the step's stored result, null for its summary after compaction. */
export interface ClaimSupport {
  step: string;
  pointer: string | null;
}

/** One sentence, list item or table row of an answer. `span` is a code point
 *  range [start, end) of `answer_markdown`. */
export interface AnswerClaim {
  id: string;
  span: [number, number];
  /** The step labels its markers name, such as `s3`. */
  citations: string[];
  evidence_status?: string | null;
  citation_status: CitationStatus;
  /** The records of the cited or matched steps that hold it. */
  support?: ClaimSupport[];
}

export interface AnswerToolUse {
  step: string;
  step_id: string;
  tool: string;
  version: number;
  is_error: boolean;
  snapshot?: string | null;
  engine?: string | null;
  queries?: { kind: "fixed" | "catalog" | "cypher"; id: string }[];
}

/** A reference from an answer. A `step` link names a step a claim cites. */
export interface AnswerLink {
  kind: string;
  ref_id: string;
  ref_revision?: number | null;
  step?: string | null;
}

export interface AnswerEnvelope {
  version: 2;
  message_id: string;
  conversation_id: string;
  kind: "answer" | "declined" | "incomplete" | "assessment_draft" | "service_draft";
  snapshot: {
    /** The run the turn was pinned to. */
    id: string | null;
    origin: "context" | "conversation" | "pointer";
    manifest_sha256?: string | null;
    degraded?: boolean | null;
    /** The other runs the answer's steps read. */
    others_used?: string[];
  };
  model: { provider: string; requested: string; served?: string | null };
  prompt_hash: string;
  tools_used: AnswerToolUse[];
  answer_markdown: string;
  claims: AnswerClaim[];
  grounding: {
    status: "grounded" | "partially-grounded" | "no-evidence";
    cited: number;
    uncited: number;
    invalid: number;
    cross_snapshot: number;
    /** Version 2. */
    matched?: number;
    process?: number;
  };
  links?: AnswerLink[];
  payload?: TurnPayload | null;
}

// --- page context: the `context` of a conversation and of a question ---------

/** The `strata/ai/page-context/v1` object, field for field as `PageContext`
 *  in src/hst/app/ai/context_resolver.py. The server rejects an unknown
 *  field or an oversize value with 422 and checks every reference before the
 *  model reads it. The user and the permissions are not part of it. */
export interface PageContext {
  version: 1;
  route: PageContextRoute;
  selection?: PageContextSelection[];
  snapshot?: PageContextSnapshot;
  flow?: PageContextFlow;
  simulation?: PageContextSimulation;
  assessment?: PageContextAssessment;
  application?: PageContextApplication;
  analysis_session?: PageContextAnalysisSession;
  application_draft?: PageContextApplicationDraft;
}

export interface PageContextRoute {
  /** At most 200 characters. */
  pathname: string;
  /** At most 500 characters. */
  search?: string;
  /** At most 20 characters. */
  pane_id?: string;
  pane_view?: PaneView;
  /** At most 40 characters. */
  section?: string;
}

export type PageContextSelectionKind =
  | "device"
  | "interface"
  | "ip"
  | "prefix"
  | "vrf"
  | "site"
  | "link"
  | "hop"
  | "service_requirement"
  | "graph_node"
  | "inventory_device";

/** One selected object. For kind `device`, `uid` is the graph uid and
 *  `inventory_id` the inventory device id when the page knows both. For kind
 *  `inventory_device`, `uid` is the inventory device id. */
export interface PageContextSelection {
  kind: PageContextSelectionKind;
  /** At most 500 characters. */
  uid: string;
  /** At most 200 characters. */
  inventory_id?: string;
  /** At most 200 characters. */
  label?: string;
  source?: "selection" | "result" | "url" | "pane";
}

/** Run ids are the run's `ts_ms` written in digits. */
export interface PageContextSnapshot {
  id: string;
  origin: "pinned" | "page-default";
  compare_id?: string;
}

export interface PageContextFlow {
  src?: string;
  dst?: string;
  port?: number | string | null;
  proto?: string | null;
  reply?: boolean;
}

export interface PageContextSimulation {
  conversation_id?: string;
  step_id?: string;
  analysis_session_id?: string;
  analysis_session_revision?: number;
  change_id?: number;
}

export interface PageContextAssessment {
  assessment_id: string;
  revision?: number;
  run_id?: string;
  finding_id?: string;
}

export interface PageContextApplication {
  application_id: string;
  revision?: number;
  /** At most 50 ids. */
  connection_ids?: string[];
}

export interface PageContextAnalysisSession {
  id: string;
  revision?: number;
}

/** One member of a generation report as the draft workspace shows it. */
export interface PageContextDraftMember {
  /** At most 200 characters. */
  path: string;
  status: "resolved" | "ambiguous" | "unresolved";
  /** At most 200 characters. */
  phrase?: string;
  /** At most 500 characters. */
  uid?: string;
  /** At most 8, each at most 500 characters. */
  candidates?: string[];
  /** The placeholder note of the member in the current YAML. At most 500 characters. */
  note?: string;
  /** At most 5, each at most 300 characters. */
  issues?: string[];
}

/** The generated Business Application draft open in the pane. */
export interface PageContextApplicationDraft {
  /** A UUID. */
  generation_id: string;
  status?: "running" | "done" | "error";
  /** The run the generation resolved against. */
  run_id?: string;
  /** The YAML on screen differs from the generated text. */
  edited?: boolean;
  /** The YAML on screen, at most 12,000 characters. */
  yaml?: string;
  /** The page cut `yaml` to its cap. */
  yaml_truncated?: boolean;
  /** At most 40. */
  members?: PageContextDraftMember[];
  /** The page left out members over the cap. */
  members_truncated?: boolean;
  /** The YAML errors on screen. At most 10, each at most 300 characters. */
  errors?: string[];
}

export interface AiTestResult {
  ok: boolean;
  provider: string;
  model: string;
  error?: string;
}

/** One row of the AI audit trail. Metadata only: no question, answer,
 *  argument or result text. */
export interface AiEvent {
  id: number;
  at: string;
  user_id: number | null;
  username: string | null;
  origin: string;
  surface: string | null;
  event: string;
  conversation_id: string | null;
  message_id: string | null;
  step_id: string | null;
  provider: string | null;
  model_requested: string | null;
  model_served: string | null;
  prompt_hash: string | null;
  tool: string | null;
  tool_version: number | null;
  snapshot: string | null;
  latency_ms: number | null;
  tokens_in: number | null;
  tokens_out: number | null;
  outcome: string;
  error_class: string | null;
  detail: Record<string, unknown> | null;
}

/** Tokens one user's AI events recorded on one UTC day. */
export interface AiDailyTokens {
  day: string;
  user_id: number | null;
  username: string | null;
  tokens_in: number;
  tokens_out: number;
}

/** GET /api/settings/ai/events */
export interface AiEvents {
  events: AiEvent[];
  daily_tokens: AiDailyTokens[];
}

export interface GraphNode {
  id: string;
  labels: string[];
  properties: Record<string, unknown>;
}

export interface GraphRelationship {
  id: string;
  type: string;
  start: string;
  end: string;
  properties: Record<string, unknown>;
}

/** The entities that the result touched, absent unless the caller asks for them. */
export interface ResultGraph {
  nodes: GraphNode[];
  relationships: GraphRelationship[];
  truncated: boolean;
}

/** `nodes` holds the element ids of the graph payload nodes that the row touched,
 *  in first-contact order. */
export interface ResultRow {
  row: unknown[];
  nodes?: string[];
}

export interface QueryResult {
  columns: string[];
  data: ResultRow[];
  truncated: boolean;
  graph?: ResultGraph;
}

// --- /api/cypher -------------------------------------------------------------

// --- /api/runs -----------------------------------------------------------------

export type RunStatus = "running" | "ok" | "error" | "cancelled";

export interface CollectionProgress {
  source: string;
  state: "collecting" | "collected" | "failed";
  phase: string;
  completed: number;
  total: number | null;
  phase_eta_s: number | null;
  updated_at_ms: number;
  enterprise?: string;
  enterprise_index?: number;
  enterprise_total?: number;
  cache_hits?: number;
  reverse_queries_saved?: number;
}

export interface Run {
  id: number;
  source: string;
  status: RunStatus;
  started_at: string;
  finished_at: string | null;
  detail: string;
  progress?: CollectionProgress[];
}

export interface RunHistory {
  sources: string[];
  /** The instance is a demo instance (HST_DEMO_FIXTURES): an admin can start the demo
   *  estate load, POST /api/runs with source "demo". */
  demo?: boolean;
  runs: Run[];
  /** With RUN_EXECUTION=queue: every `collect.run` job that is queued or
   *  running, oldest first, however many newer runs or jobs there are. A queued
   *  run has no row in `runs` until an executor claims its job. */
  pending_runs?: Job[];
}

/** POST /api/runs with RUN_EXECUTION=queue: the queued `collect.run` job in place
 *  of a run row. The run row appears when an executor claims the job. */
export interface QueuedRun {
  job_id: number;
  kind: string;
  source: string;
  status: "queued";
  enqueued_at: string;
}

// --- /api/runs/http-traces ------------------------------------------------------

/** One sealed HTTP exchange trace of a fetch (collectors/http_trace.py). `source`
 *  and `host` are the raw store's path segments, which the download needs. */
export interface HttpTraceFile {
  source: string;
  host: string;
  run_id: string;
  fetch_ts_ms: number;
  size: number;
}

export interface HttpTraces {
  /** the `HST_HTTP_TRACE` setting as set: source names, `*`, or empty for off */
  enabled: string;
  traces: HttpTraceFile[];
}

// --- /api/debug-capture ---------------------------------------------------------

export interface DebugSource {
  name: string;
  type: string;
  /** epoch ms the capture switch turns off; null while it is off */
  until_ms: number | null;
  by: string | null;
}

export interface DebugOpenStep {
  step: string;
  command: string | null;
  started_ms: number | null;
}

/** One load's record file. `finished` false with open steps is a load the
 *  process did not survive: the last open step is where it stopped. */
export interface DebugCapture {
  id: string;
  /** the raw-store directory segment */
  source: string;
  /** the source row name, where one matches the segment */
  source_name: string;
  host: string;
  run_id: string;
  loads: number;
  begin_ms: number | null;
  last_ms: number | null;
  finished: boolean;
  status: string | null;
  error: string | null;
  open_steps: DebugOpenStep[];
  peak_rss_kb: number | null;
  has_stack: boolean;
  unreadable_lines: number;
  size: number;
}

export interface DebugOverview {
  sources: DebugSource[];
  captures: DebugCapture[];
  limits: {
    capture_hours: number;
    stack_after_s: number;
    reparse_memory_mb: number;
    reparse_timeout_s: number;
  };
}

export type ReparseState = "running" | "ok" | "error" | "memory" | "timeout" | "killed";

export interface DebugPayload {
  id: string;
  source: string;
  host: string;
  run_id: string;
  fetch_ts_ms: number;
  size: number;
  has_capture: boolean;
  reparse: {
    state: ReparseState;
    error?: string | null;
    started_ms?: number | null;
    finished_ms?: number | null;
    exit_code?: number | null;
    peak_rss_kb?: number | null;
  } | null;
}

export interface DebugPayloads {
  source: string;
  payloads: DebugPayload[];
}

// --- /api/jobs -----------------------------------------------------------------

/** `queued` with an attempt above 1 means "waiting to retry". */
export type JobState = "queued" | "running" | "ok" | "error" | "dead";

export interface Job {
  progress?: CollectionProgress[];
  id: number;
  /** e.g. "maintenance.prune_graph" */
  kind: string;
  /** Null for everything maintenance queues. */
  source: string | null;
  device: string | null;
  state: JobState;
  attempt: number;
  max_attempts: number;
  enqueued_at: string;
  started_at: string | null;
  finished_at: string | null;
  /** When the job becomes claimable: its scheduled turn, or its retry backoff. */
  not_before: string;
  /** Seconds the last attempt took; null while it has not finished one. */
  duration_s: number | null;
  /** What the job did, or why it failed. Written for operators. */
  detail: string;
  /** "scheduler", or "<origin>:<user id>" for a job an account asked for: "runs:"
   *  (a run queued through POST /api/runs), "debug:" (a queued re-parse),
   *  "inventory:" or "assessment:". */
  triggered_by: string;
}

export interface JobHistory {
  jobs: Job[];
  /** How many jobs sit in each state; states with none are absent. */
  depth: Partial<Record<JobState, number>>;
}

// --- /api/source-types / /api/sources ---------------------------------------

// A property node in a pydantic `model_json_schema()` `properties` map.
export interface SourceTypeField {
  type?: string;
  title?: string;
  description?: string;
  format?: string;
  /** With `format: "source"`: the field names another configured source, and
   * `sourceType` narrows the pick to sources of that type. */
  sourceType?: string;
  writeOnly?: boolean;
  default?: unknown;
  $ref?: string;
  const?: string;
  /** A closed set of values (a pydantic Literal). */
  enum?: Array<string | number>;
  properties?: Record<string, SourceTypeField>;
  required?: string[];
  oneOf?: SourceTypeField[];
  anyOf?: SourceTypeField[];
  allOf?: SourceTypeField[];
  discriminator?: { propertyName: string; mapping?: Record<string, string> };
}

export interface SourceTypeSchema {
  type: string;
  title?: string;
  properties: Record<string, SourceTypeField>;
  required?: string[];
}

// sources.py's `source_types()` returns one entry per collector type.
/** Declared by the collector class; a group carries a device list, an
 * orchestrator discovers its own. */
export type SourceKind = "group" | "orchestrator";

export interface SourceType {
  type: string;
  kind: SourceKind;
  schema: SourceTypeSchema;
}

export interface SourceTypesResponse {
  types: SourceType[];
}

export interface Source {
  name: string;
  type: string;
  kind: SourceKind;
  config: Record<string, unknown>;
  secrets: Record<string, boolean>;
  /** True when the stored secrets blob does not decrypt under the current key. */
  secrets_unreadable?: boolean;
  enabled: boolean;
  updated_at: string | null;
  /** Set on a create or edit response when another controller source shares
   * this row's routing scope. Absent on list rows. */
  warnings?: string[];
}

export interface SourcesResponse {
  sources: Source[];
}

/** Groups use the source row and response shape. */
export type Group = Source;

export interface EffectiveGroupDevice {
  host: string;
  device_uids: string[];
  site: string | null;
  values: { routing_scope: string | null; l2fabric: string | null };
  origins: { site: string; routing_scope: string; l2fabric: string };
}

export interface GroupEffectiveResponse {
  devices: EffectiveGroupDevice[];
}

export interface SourceCreateRequest {
  name: string;
  type: string;
  config?: Record<string, unknown>;
  enabled?: boolean;
}

export interface SourcePatchRequest {
  config?: Record<string, unknown>;
  enabled?: boolean;
}

export interface SourceTestResult {
  ok: boolean;
  detail: string;
}

// --- /api/sources/{name}/devices --------------------------------------------

export interface SourceDevice {
  host: string;
  /** null = the device follows the group's port */
  port: number | null;
  enabled: boolean;
  updated_at: string | null;
  /** The device's collection record (`device_status`), or null before its first attempt. */
  status?: SourceDeviceStatus | null;
}

/** One device's collection record. */
export interface SourceDeviceStatus {
  last_attempt_at: string | null;
  last_success_at: string | null;
  consecutive_failures: number;
  last_error: string;
  fetch_ms: number | null;
  load_ms: number | null;
}

export interface SourceDevicesResponse {
  devices: SourceDevice[];
}

export interface SourceDeviceIn {
  host: string;
  port?: number | null;
  enabled?: boolean;
}

// --- /api/auth (SSO: providers, group mappings) -----------------------------

export type ProviderKind = "oidc" | "saml";

/** "none" creates or keeps the account disabled. */
export type DefaultRole = Role | "none";

/** The public provider descriptor for the login page (GET /api/auth/providers). */
export interface AuthProviderPublic {
  name: string;
  kind: ProviderKind;
  label: string;
}

export interface AuthProvidersResponse {
  providers: AuthProviderPublic[];
  local_login_enabled: boolean;
}

/** GET/PUT /api/settings/auth. PUT can come back 409 with `{"error": ...}`
 *  when the break-glass guard refuses (no other login path would remain). */
export interface AuthSettings {
  local_login_enabled: boolean;
}

/** The admin-facing provider row holds no secret. */
export interface AuthProvider {
  id: number;
  name: string;
  kind: ProviderKind;
  enabled: boolean;
  config: Record<string, unknown>;
  has_secret: boolean;
  created_at: string;
  updated_at: string;
  /** A saml provider has this field. Null when HST_PUBLIC_URL is empty. */
  sp_entity_id?: string | null;
  /** A saml provider has this field. Null when HST_PUBLIC_URL is empty. */
  sp_acs_url?: string | null;
  /** An oidc provider has this field. Null when HST_PUBLIC_URL is empty. */
  redirect_uri?: string | null;
}

export interface AuthProviderCreateRequest {
  name: string;
  kind: ProviderKind;
  config: Record<string, unknown>;
  /** The write-only client_secret of an oidc provider. */
  secret?: string;
}

export interface AuthProviderPatchRequest {
  config?: Record<string, unknown>;
  secret?: string;
  enabled?: boolean;
}

export interface AuthProviderTestResult {
  ok: boolean;
  detail: string;
}

/** POST upserts a mapping by `group_name`. */
export interface GroupMapping {
  group_name: string;
  role: Role;
}

export interface GroupMappingRequest {
  group_name: string;
  role: Role;
}

// --- /api/users (admin) -------------------------------------------------------

/** "mapped" derives the role from the group mappings at every SSO login. */
export type RoleSource = "local" | "mapped";

export interface User {
  id: number;
  username: string;
  role: Role;
  /** Origin of `role` (RoleSource). */
  role_source: RoleSource;
  /** False for SSO-provisioned accounts (`password_hash IS NULL` server-side). */
  has_password: boolean;
  /** Provider names this account is linked to. Empty means a local account. */
  identities: string[];
  disabled: boolean;
  created_at: string;
}

export interface UsersResponse {
  users: User[];
}

export interface UserCreateRequest {
  username: string;
  password: string;
  role: Role;
}

export interface UserPatchRequest {
  role?: Role;
  /** The value "mapped" clears a local role override. */
  role_source?: "mapped";
  disabled?: boolean;
  password?: string;
}

/** `age_ms` is measured against the run key. */
export interface TableFreshness {
  status: string;
  observed_ms: number | null;
  age_ms: number | null;
}

/** A drawn device with the freshness fields of the pinned run. */
export interface MapDevice {
  uid: string;
  name: string;
  role: string | null;
  /** The place in the design from the run's role step (core/device_roles.py),
   *  e.g. "core" or "access"; null when no hostname token matched. */
  tier?: string | null;
  /** Where `role` came from: collector, evidence, hostname or default. */
  role_basis?: string | null;
  vendor: string | null;
  model: string | null;
  mgmt_ip: string | null;
  site: string | null;
  carried?: boolean;
  carried_reason?: string | null;
  last_seen?: number | null;
  tables?: Record<string, TableFreshness>;
}

export interface MapLink {
  a_dev: string;
  a_port: string | null;
  b_dev: string;
  b_port: string | null;
  source: string | null;
}

/** One client endpoint. The fields after `ips` come from GET /api/topology;
 *  `mac` is the canonical 12 hex digits, `vendor` the vendor of the MAC as the
 *  source names it, `last_seen` when the source last saw it (epoch ms), and
 *  `bd` the bridge domain uid of its segment. */
export interface MapClient {
  name: string;
  uid: string;
  ips: string[];
  mac?: string | null;
  wired?: boolean | null;
  vendor?: string | null;
  last_seen?: number | null;
  bd?: string | null;
}

/** Endpoints rolled up per attachment point: a port of a device (`port`), or
 *  an access point and SSID (`ssid`). `by_bd` counts them per bridge domain;
 *  `clients` is the first 50. */
export interface MapClientGroup {
  dev: string;
  port?: string | null;
  ssid: string | null;
  count: number;
  by_bd?: Record<string, number>;
  clients: MapClient[];
}

/** One VLAN on one device: the ports that carry it (trunk or access, as the
 *  platform states it), which of those are native, and the SVI bound to it.
 *  `segment` is the bridge domain's name when the device states one, and `bd`
 *  its uid. */
export interface MapVlan {
  dev: string;
  vid: number;
  name: string | null;
  segment: string | null;
  bd?: string | null;
  ports: string[];
  native: string[];
  svi: string | null;
}

export interface MapSubnetMember {
  dev: string;
  iface: string;
  ip: string;
  /** hsrp or vrrp when this address is a first-hop virtual address */
  fhrp: string | null;
}

/** One connected prefix in one routing domain, with every interface address on it. */
export interface MapSubnet {
  cidr: string;
  af: number;
  vrf: string;
  domain: string | null;
  members: MapSubnetMember[];
}

// --- /api/sites/graph (the site map) -----------------------------------------

export type SiteEdgeKind = "cable" | "circuit" | "tunnel" | "l3" | "bgp";

export interface SiteExit {
  dev: string;
  name: string;
  kind: string | null;
  carrier: string | null;
  bandwidth_mbps: number | null;
}

export interface SiteGraphSite {
  code: string;
  name: string;
  lat: number | null;
  lon: number | null;
  devices: number;
  /** the graph Site's own kind, e.g. colo for an Equinix site */
  kind?: string | null;
  /** how many of the site's devices are in each tier (core/device_roles.py) */
  tiers?: Record<string, number>;
  /** one-ended WAN links at this site: exits, not edges */
  exits: SiteExit[];
}

/** One boundary pair. The fields depend on the kind (routes/site_graph.py):
 *  every kind has a_dev/a_name and b_dev/b_name, and the a_ side is the
 *  edge's `a` site. */
export type SitePair = Record<string, string | number | boolean | null>;

export interface SiteGraphEdge {
  a: string;
  b: string;
  kind: SiteEdgeKind;
  count: number;
  /** the first SAMPLE_PAIRS of them */
  pairs: SitePair[];
}

export interface SiteGraphPayload {
  sites: SiteGraphSite[];
  edges: SiteGraphEdge[];
  /** cross-site relationships whose far end no site claims */
  unplaced: { site: string; kind: SiteEdgeKind; count: number }[];
  /** connected prefixes held at too many sites to pair: one record each, no edge */
  shared_subnets?: { cidr: string; domain: string; sites: number; members: number }[];
  /** BGP sessions whose peer address more than one device holds, left out of the edges */
  ambiguous?: { site: string; kind: SiteEdgeKind; count: number }[];
}

export interface SiteTracePair {
  src: string;
  dst: string;
  /** the context each prefix was traced in */
  src_context?: string | null;
  dst_context?: string | null;
  detail: string | null;
  result: ResultValue | null;
  blocked: boolean | null;
}

export interface SiteTraceResponse {
  src_site: string;
  dst_site: string;
  /** the run both sites' prefixes and every trace were read from */
  snapshot?: number | null;
  pairs: SiteTracePair[];
  truncated: boolean;
  total_pairs?: number;
  note?: string;
}

// --- /api/snapshots (time travel) -------------------------------------------

/** The kind of run that produced the snapshot. "full" is a scheduled cycle
 *  over every source. Each other kind takes the rest from `parent`. */
export type SnapshotKind = "full" | "partial" | "refresh" | "device";

export interface Snapshot {
  /** Same value as `ts_ms`, as a string: the id `/api/diff` and `/api/path`
   *  take on the wire. */
  id: string;
  ts_ms: number;
  created: string;
  nodes: number;
  rels: number;
  sources_fresh: string[];
  sources_carried: string[];
  sources_failed: string[];
  degraded: boolean;
  kind: SnapshotKind;
  /** The ts_ms number of the run this one was built from. */
  parent: number | null;
}

export interface SnapshotList {
  /** Newest first. */
  snapshots: Snapshot[];
  current: number | null;
  /** Whether older runs exist beyond this page (F-098). */
  truncated: boolean;
  /** The state of the run `current` names, with its per-device freshness
   *  summary (FEAT-05). Null before the first run is published. */
  run?: CycleRunStatus | null;
}

// --- /api/path/vrfs ---------------------------------------------------------

/** One VRF name of a run, listed once, and the number of devices that have a
 *  VRF of that name. `name` is the value GET /api/path accepts as `start_vrf`. */
export interface StartVrf {
  name: string;
  devices: number;
}

export interface StartVrfList {
  vrfs: StartVrf[];
}

// --- /api/diff (time travel) ------------------------------------------------

export interface DiffCount {
  added: number;
  removed: number;
  changed: number;
}

export interface DiffCounts {
  nodes: DiffCount;
  rels: DiffCount;
}

export interface DiffNode {
  uid: string;
  label: string;
  name: string;
}

/** `changes` maps a property name to its `[before, after]` pair. */
export interface DiffNodeChanged extends DiffNode {
  changes: Record<string, [unknown, unknown]>;
}

export interface DiffRel {
  type: string;
  start: string;
  end: string;
}

export interface DiffRelChanged extends DiffRel {
  changes: Record<string, [unknown, unknown]>;
}

export interface DiffResponse {
  a: number;
  b: number;
  counts: DiffCounts;
  nodes: { added: DiffNode[]; removed: DiffNode[]; changed: DiffNodeChanged[] };
  rels: { added: DiffRel[]; removed: DiffRel[]; changed: DiffRelChanged[] };
  /** Detail lists above are capped at 500 entries. */
  truncated: boolean;
}

// MTU contract v1. Additive; absent means not assessed.

export interface MtuConstraint {
  subject_uid: string;
  enforcement_key: string;
  enforcement: "l2" | "l3" | "source" | "destination" | "tunnel" | "fabric" | "control_plane" | "path" | "unknown";
  metric: "l2_max_frame_bytes" | "l2_payload_mtu_bytes" | "ipv4_mtu_bytes" | "ipv6_mtu_bytes" | "path_pmtu_bytes" | "unknown";
  direction: "tx" | "rx" | "both" | "unknown";
  af?: 4 | 6 | null;
  bound_kind: "ceiling" | "acceptance_lower_bound" | "unknown";
  value_bytes?: number | null;
  traffic_class?: string | null;
  tag_depth?: number | null;
  evidence_uids?: (string)[];
  evidence_quality?: (string)[];
  inherited_from?: (string)[];
  gaps?: ("MTU_NOT_CAPTURED" | "MTU_SEMANTICS_UNKNOWN" | "MTU_SOURCE_CONFLICT" | "MTU_POLICY_UNRESOLVED" | "MTU_ENDPOINT_UNKNOWN" | "MTU_RECEIVE_LIMIT_UNKNOWN" | "MTU_ENCAP_UNKNOWN" | "MTU_PATH_COVERAGE_INCOMPLETE" | "MTU_FRAGMENTATION_UNMODELED" | "MTU_PMTUD_FEEDBACK_UNKNOWN" | "MTU_EVIDENCE_STALE" | "MTU_CLASS_UNKNOWN" | "MTU_SNAPSHOT_UNPINNED" | "MTU_LENGTH_UNSUPPORTED")[];
}

export interface MtuContext {
  af: 4 | 6;
  direction?: "tx" | "rx";
  enforcement?: "l2" | "l3" | "source" | "destination" | "tunnel" | "fabric" | "control_plane" | "path" | "unknown";
  traffic_class?: string | null;
  tag_depth?: number | null;
}

export interface MtuCoverage {
  complete?: boolean;
  candidate_set_complete?: boolean;
  constraints_complete?: boolean;
  exact_path_known?: boolean;
  truncated?: boolean;
  gaps?: ("MTU_NOT_CAPTURED" | "MTU_SEMANTICS_UNKNOWN" | "MTU_SOURCE_CONFLICT" | "MTU_POLICY_UNRESOLVED" | "MTU_ENDPOINT_UNKNOWN" | "MTU_RECEIVE_LIMIT_UNKNOWN" | "MTU_ENCAP_UNKNOWN" | "MTU_PATH_COVERAGE_INCOMPLETE" | "MTU_FRAGMENTATION_UNMODELED" | "MTU_PMTUD_FEEDBACK_UNKNOWN" | "MTU_EVIDENCE_STALE" | "MTU_CLASS_UNKNOWN" | "MTU_SNAPSHOT_UNPINNED" | "MTU_LENGTH_UNSUPPORTED")[];
  unresolved_subjects?: (string)[];
  /** Stable codes naming what the twin does not cover, populated only for
   * a "fits_known_limits" outcome: "source-endpoint", "destination-endpoint",
   * "path-beyond-twin". */
  uncovered?: ("source-endpoint" | "destination-endpoint" | "path-beyond-twin")[];
}

export interface MtuEncapsulation {
  kind: "vxlan" | "gre" | "wireguard" | "ipsec" | "vlan" | "pppoe" | "mpls" | "macsec" | "unknown";
  operation?: "encapsulate" | "decapsulate";
  profile_id?: string;
  outer_af?: 4 | 6 | null;
  parameters_json?: string;
  evidence_uids?: (string)[];
}

export interface MtuFeedback {
  outcome?: "not_assessed" | "permitted" | "blocked" | "unknown";
  packet?: MtuPacketDescriptor | null;
  evidence_uids?: (string)[];
  gaps?: ("MTU_NOT_CAPTURED" | "MTU_SEMANTICS_UNKNOWN" | "MTU_SOURCE_CONFLICT" | "MTU_POLICY_UNRESOLVED" | "MTU_ENDPOINT_UNKNOWN" | "MTU_RECEIVE_LIMIT_UNKNOWN" | "MTU_ENCAP_UNKNOWN" | "MTU_PATH_COVERAGE_INCOMPLETE" | "MTU_FRAGMENTATION_UNMODELED" | "MTU_PMTUD_FEEDBACK_UNKNOWN" | "MTU_EVIDENCE_STALE" | "MTU_CLASS_UNKNOWN" | "MTU_SNAPSHOT_UNPINNED" | "MTU_LENGTH_UNSUPPORTED")[];
}

export interface MtuFinding {
  code: "MTU_NORMALIZED_DIFFERENCE" | "MTU_CAPACITY_DEFICIT" | "MTU_POLICY_DRIFT" | "MTU_ADJACENCY_DISCREPANCY" | "MTU_LAG_INCONSISTENCY" | "MTU_PMTUD_BLACKHOLE_RISK" | "MTU_NOT_CAPTURED" | "MTU_SEMANTICS_UNKNOWN" | "MTU_SOURCE_CONFLICT" | "MTU_POLICY_UNRESOLVED" | "MTU_ENDPOINT_UNKNOWN" | "MTU_RECEIVE_LIMIT_UNKNOWN" | "MTU_ENCAP_UNKNOWN" | "MTU_PATH_COVERAGE_INCOMPLETE" | "MTU_FRAGMENTATION_UNMODELED" | "MTU_PMTUD_FEEDBACK_UNKNOWN" | "MTU_EVIDENCE_STALE" | "MTU_CLASS_UNKNOWN" | "MTU_SNAPSHOT_UNPINNED" | "MTU_LENGTH_UNSUPPORTED";
  severity?: "info" | "risk" | "failure" | "gap";
  detail: string;
  subject_uids?: (string)[];
  stage_ids?: (string)[];
  evidence_uids?: (string)[];
  af?: 4 | 6 | null;
  direction?: "forward" | "reverse" | null;
  observed_bytes?: number | null;
  required_bytes?: number | null;
  deficit_bytes?: number | null;
  scope?: string | null;
}

export interface MtuObservation {
  uid: string;
  contract_version?: string;
  normalization_version?: string;
  subject_uid: string;
  source: string;
  source_target: string;
  source_field: string;
  raw_value_json: string;
  raw_basis?: "ip_packet" | "ethernet_frame_excluding_fcs" | "ethernet_frame_including_fcs" | "ethernet_payload" | "unknown";
  raw_units?: string;
  metric?: "l2_max_frame_bytes" | "l2_payload_mtu_bytes" | "ipv4_mtu_bytes" | "ipv6_mtu_bytes" | "path_pmtu_bytes" | "unknown";
  normalized_value?: number | null;
  direction?: "tx" | "rx" | "both" | "unknown";
  bound_kind?: "ceiling" | "acceptance_lower_bound" | "unknown";
  af?: 4 | 6 | null;
  enforcement?: "l2" | "l3" | "source" | "destination" | "tunnel" | "fabric" | "control_plane" | "path" | "unknown";
  enforcement_key?: string;
  traffic_class?: string | null;
  assertion_kind: "configured" | "operational" | "intent" | "hardware_max" | "measurement";
  resolution_state?: "explicit" | "inherited" | "profile_default" | "unknown" | "unsupported" | "conflict";
  policy_ref?: string | null;
  scope?: string;
  selector_json?: string;
  profile_id?: string;
  profile_version?: string;
  collector_version?: string;
  raw_evidence_ref?: string;
  observed_at_ms?: number | null;
  dependency_uids?: (string)[];
  tag_accounting?: "included" | "extra_allowance" | "unknown";
  tag_depth?: number | null;
  tag_allowance_bytes?: number | null;
  gaps?: ("MTU_NOT_CAPTURED" | "MTU_SEMANTICS_UNKNOWN" | "MTU_SOURCE_CONFLICT" | "MTU_POLICY_UNRESOLVED" | "MTU_ENDPOINT_UNKNOWN" | "MTU_RECEIVE_LIMIT_UNKNOWN" | "MTU_ENCAP_UNKNOWN" | "MTU_PATH_COVERAGE_INCOMPLETE" | "MTU_FRAGMENTATION_UNMODELED" | "MTU_PMTUD_FEEDBACK_UNKNOWN" | "MTU_EVIDENCE_STALE" | "MTU_CLASS_UNKNOWN" | "MTU_SNAPSHOT_UNPINNED" | "MTU_LENGTH_UNSUPPORTED")[];
}

export interface MtuPacketDescriptor {
  af: 4 | 6;
  source_ip: string;
  destination_ip: string;
  icmp_type: number;
  icmp_code: number;
  quoted_flow_json: string;
  connection_id: string;
  advertised_mtu_bytes?: number | null;
}

export interface MtuResult {
  observation_provenance?: Record<string, Record<string, unknown>>;
  contract_version?: string;
  evaluation_version?: string;
  mode?: "off" | "inventory" | "unfragmented" | "packet";
  af?: 4 | 6 | null;
  direction?: "forward" | "reverse";
  connection_id?: string;
  lane?: string | null;
  requested_bytes?: number | null;
  outcome?: "not_assessed" | "pass" | "fail" | "unknown" | "fragmentation_required" | "conditional" | "fits_known_limits";
  known_ceiling_bytes?: number | null;
  guaranteed_bytes?: number | null;
  coverage?: MtuCoverage;
  evidence_quality?: (string)[];
  bottleneck_stage_ids?: (string)[];
  findings?: (MtuFinding)[];
  unresolved_subjects?: (string)[];
  stages?: (MtuStage)[];
  candidates?: (MtuResult)[];
  lanes?: (MtuResult)[];
  connections?: (MtuResult)[];
  fingerprint?: string | null;
  feedback?: (MtuFeedback)[];
  observations?: (MtuObservation)[];
}

export interface MtuStage {
  stage_id: string;
  connection_id?: string;
  direction?: "forward" | "reverse";
  lane?: string;
  region?: string;
  depth?: number;
  enforcement?: "l2" | "l3" | "source" | "destination" | "tunnel" | "fabric" | "control_plane" | "path" | "unknown";
  applicability?: "applicable" | "not_applicable" | "unknown";
  ingress_subject_uid?: string | null;
  egress_subject_uid?: string | null;
  peer_subject_uid?: string | null;
  context: MtuContext;
  constraints?: (MtuConstraint)[];
  coverage?: MtuCoverage;
  encapsulation?: (MtuEncapsulation)[];
  candidate_set_id?: string | null;
  candidate_id?: string | null;
  selection?: "selected" | "eligible" | "possible" | "unknown";
  connection_reset?: boolean;
  fragmentation_supported?: boolean | null;
}

export interface MtuRequest {
  mode?: "off" | "inventory" | "unfragmented" | "packet";
  ip_packet_bytes?: number | null;
  ipv4_df?: boolean | null;
  reply_ip_packet_bytes?: number | null;
  traffic_class?: string | null;
}

export interface MtuAuditItem {
  subject_uid: string;
  peer_uid: string;
  resolutions: (MtuResolution)[];
  findings: (MtuFinding)[];
}

export interface MtuResolution {
  constraints?: (MtuConstraint)[];
  configured?: (MtuConstraint)[];
  intent?: (MtuConstraint)[];
  hardware?: (MtuConstraint)[];
  measurements?: (MtuConstraint)[];
  observations?: (MtuObservation)[];
  findings?: (MtuFinding)[];
  gaps?: ("MTU_NOT_CAPTURED" | "MTU_SEMANTICS_UNKNOWN" | "MTU_SOURCE_CONFLICT" | "MTU_POLICY_UNRESOLVED" | "MTU_ENDPOINT_UNKNOWN" | "MTU_RECEIVE_LIMIT_UNKNOWN" | "MTU_ENCAP_UNKNOWN" | "MTU_PATH_COVERAGE_INCOMPLETE" | "MTU_FRAGMENTATION_UNMODELED" | "MTU_PMTUD_FEEDBACK_UNKNOWN" | "MTU_EVIDENCE_STALE" | "MTU_CLASS_UNKNOWN" | "MTU_SNAPSHOT_UNPINNED" | "MTU_LENGTH_UNSUPPORTED")[];
}

/** GET /api/sdwan/edges (app/routes/sdwan.py): the edge picker. */
export interface SdwanEdgeSummary {
  uid: string;
  name: string;
  /** "hub" on a hub; null on a branch edge */
  role: string | null;
  location: string | null;
  country: string | null;
  site: string | null;
}

export interface SdwanEdgesResponse {
  edges: SdwanEdgeSummary[];
}

export interface SdwanWanLink {
  uid: string;
  name: string | null;
  kind: string | null;
  carrier: string | null;
  provider: string | null;
  public_ip: string | null;
  mode: string | null;
  interface: string | null;
  up_mbps: number | null;
  down_mbps: number | null;
  backup_only: boolean;
}

export interface SdwanTunnel {
  uid: string;
  /** the edge interface the tunnel leaves on: the key to its WAN link */
  interface: string | null;
  /** the hub, branch or gateway uid; null when the far end is not in the graph */
  peer: string | null;
  /** "branch" on a tunnel of a picked hub that ends on a branch edge */
  peer_kind: "hub" | "branch" | "gateway" | null;
  peer_ip: string | null;
}

export interface SdwanCable {
  a_dev: string;
  a_port: string | null;
  b_dev: string;
  b_port: string | null;
  source: string | null;
}

/** One SdwanPolicyRule: flat match_* and action
 *  properties; an absent property is a field the rule leaves open. */
export interface SdwanPolicyRule {
  name?: string | null;
  position: number;
  default?: boolean;
  segment_id?: string | null;
  segment_name?: string | null;
  match_summary?: string | null;
  [prop: string]: string | number | boolean | string[] | null | undefined;
}

export interface SdwanPolicy {
  uid: string;
  name: string | null;
  /** null when the run predates the rule nodes, and after a refused QOS
   *  read, which also sets capability_gap */
  rule_count: number | null;
  capability_gap: string | null;
  rules: SdwanPolicyRule[];
}

/** GET /api/sdwan/topology?edge= (app/routes/sdwan.py). */
export interface SdwanTopology {
  edge: {
    uid: string;
    name: string;
    model?: string | null;
    location?: string | null;
    city?: string | null;
    country?: string | null;
    ha_type?: string | null;
    role?: string | null;
  };
  links: SdwanWanLink[];
  tunnels: SdwanTunnel[];
  hubs: Array<{ uid: string; name: string; site: string | null }>;
  /** the branch edges at the far end of the tunnels of a picked hub */
  branches?: Array<{ uid: string; name: string; site: string | null }>;
  gateways: Array<{ uid: string; name: string }>;
  devices: Array<{ uid: string; name: string; platform: string | null; site: string | null }>;
  /** `other_devices`: the devices of the site with no cable to a hub, counted, not drawn */
  sites: Array<{ code: string; name: string; other_devices?: number }>;
  cables: SdwanCable[];
  policy: SdwanPolicy | null;
}

// --- /api/equinix -------------------------------------------------------------

/** One catalog query of the `equinix` group (hst/queries.py). */
export interface EquinixQuery {
  key: string;
  title: string;
  description: string | null;
}

/** GET /api/equinix/metros (app/routes/equinix.py). */
export interface EquinixMetrosResponse {
  metros: Array<{ metro: string; ports: number; ibxs: string[]; edge_devices: number }>;
  queries: EquinixQuery[];
}

export interface EquinixPort {
  uid: string;
  name: string;
  ibx: string | null;
  state: string | null;
  speed_mbps: number | null;
  redundancy: string | null;
  lag: string | null;
  cable_ids: string[];
  /** the switch port that realizes the Fabric port; `by` is `operator`, or the reasoner's evidence */
  bound: { device: string; port: string; port_name: string | null; by: string | null } | null;
  /** why no switch port realizes the Fabric port, when the run states it */
  unbound?: {
    reason: "binding-refused" | "cable-conflict" | "several-ports" | "several-fabric-ports";
    ports: string[];
  } | null;
}

export interface EquinixEdgeDevice {
  uid: string;
  name: string;
  vendor: string | null;
  model: string | null;
  role: string | null;
  ibx: string | null;
  status: string | null;
  /** the device uid of the source's edge_device_bindings line */
  bound_device: string | null;
  same_as: string | null;
  same_as_name: string | null;
}

/** One end of a circuit: the account's Fabric port, the account's Network Edge interface, a cloud
 *  on-ramp by provider name, or another party's end. */
export interface EquinixEnd {
  kind: "port" | "edge" | "provider" | "other";
  node?: string;
  name: string | null;
  ibx?: string | null;
  metro?: string | null;
  device?: string | null;
  device_name?: string | null;
  tag: number | null;
}

export interface EquinixCircuit {
  uid: string;
  name: string | null;
  type: string | null;
  state: string | null;
  bandwidth_mbps: number | null;
  /** whether the reasoner drew a link between two device ports for it */
  cabled: boolean;
  a: EquinixEnd | null;
  z: EquinixEnd | null;
}

/** GET /api/equinix/metro?metro= (app/routes/equinix.py). */
export interface EquinixMetroView {
  metro: string;
  ports: EquinixPort[];
  devices: Array<{ uid: string; name: string; platform: string | null; kind: "switch" }>;
  edge_devices: EquinixEdgeDevice[];
  circuits: EquinixCircuit[];
  ended_circuits: number;
  other_circuits?: Record<string, number>;
  queries: EquinixQuery[];
}

/** GET /api/topology: the unified map's view model (hst/diagram/planner.py).
 *  The nodes form one tree, site > block > group > device, by `parent`. */
export interface TopologyNode {
  id: string;
  kind: "site" | "block" | "group" | "device";
  parent: string | null;
  label: string;
  /** block: internet-edge, wan-edge, campus, dc, firewall or other */
  block_kind?: string;
  /** firewall block: the blocks it faces */
  faces?: string[];
  /** group: the redundancy group kind, e.g. vpc or cp-cluster */
  group_kind?: string | null;
  role?: string | null;
  tier?: string | null;
  role_basis?: string | null;
  /** device: tier, inferred from the cabled neighbors, or none */
  block_basis?: string;
  vendor?: string | null;
  model?: string | null;
  /** device: the management address the collector reported */
  mgmt_ip?: string | null;
  /** device: the hop count from the outer devices; null when no cable reaches it */
  depth?: number | null;
  /** device: why it is an outer device, when it is one */
  anchor?: string | null;
  /** device: the order of its tier inside its block, top first */
  partition?: number | null;
  /** device: whether this run observed it, as on MapDevice */
  carried?: boolean;
  carried_reason?: string | null;
  last_seen?: number | null;
  tables?: Record<string, TableFreshness>;
}

export interface TopologyEnd {
  dev: string;
  port: string | null;
}

/** One cable, outer end first. A lateral cable joins two devices at one depth. */
export interface TopologyCable {
  id: string;
  from: TopologyEnd;
  to: TopologyEnd;
  source: string | null;
  /** the link speed in Mbit/s: the derived cable speed, else the lower port speed */
  speed_mbps?: number | null;
  lateral: boolean;
}

/** A cable with one end outside the drawing, or a LAG member's CDP or LLDP
 *  neighbor that no collector reached (`far_dev` empty, `source` "cdp, no cable" or "lldp, no cable"). */
export interface TopologyExit {
  dev: string;
  port: string | null;
  far_dev: string;
  far_port: string | null;
  far_name: string;
  source: string | null;
}

export interface TopologyLag {
  id: string;
  dev: string;
  name: string | null;
  cables: string[];
  far: string[];
  ports_without_cable: string[];
  multi_chassis: boolean;
  basis: string;
}

export interface TopologyModel {
  snapshot: number | null;
  nodes: TopologyNode[];
  cables: TopologyCable[];
  exits: TopologyExit[];
  lags: TopologyLag[];
  split_groups: { uid: string; kind: string | null; name: string | null; members: string[] }[];
  /** endpoints per attachment point of a drawn device */
  clients?: MapClientGroup[];
  /** the facts of the L2 and L3 layers (diagram/overlay.ts) */
  vlans?: MapVlan[];
  subnets?: MapSubnet[];
  /** one per bridge domain of the drawing (hst/diagram/segments.py) */
  segments?: TopologySegment[];
}

/** A gateway of a segment: an interface ATTACHED_TO its bridge domain,
 *  one row per address on a connected prefix. `basis`
 *  says how: an SVI (svi), a subinterface by its VLAN tag (subif), an untagged
 *  routed port by the native VLAN of the switch port at the far end of its
 *  cable (cable), or, for a run with no attachment, an interface on the prefix
 *  of the segment's clients (cidr). `ip` is null for an interface with no address. */
export interface SegmentGateway {
  dev: string;
  iface: string;
  ip: string | null;
  cidr: string | null;
  af: number | null;
  vrf: string | null;
  domain: string | null;
  fhrp: string | null;
  /** whether the graph marks the interface GATEWAY_FOR the prefix, the only gateway a trace uses */
  routes?: boolean | null;
  basis: "svi" | "subif" | "cable" | "cidr";
}

/** The ports of one device that carry a segment; `access` are the native
 *  ports with no cable. */
export interface SegmentCarrier {
  dev: string;
  ports: string[];
  native: string[];
  access: string[];
}

export interface TopologySegment {
  bd: string;
  /** set when the drawing holds devices of more than one site: the bridge domain is
   *  one per VLAN id on the default fabric, and its record is kept per site */
  site?: string | null;
  vid: number | null;
  name: string | null;
  /** the gateways' prefixes, else those of the clients, most clients first */
  cidrs: string[];
  cidr_basis: "gateway" | "clients" | null;
  gateways: SegmentGateway[];
  carriers: SegmentCarrier[];
  clients: number;
  attachments: { dev: string | null; port: string | null; ssid: string | null; count: number }[];
}

/** GET /api/topology/segment: one page of the clients of one segment. */
export interface SegmentClientsPage {
  snapshot: number | null;
  bd: string;
  total: number;
  offset: number;
  limit: number;
  clients: (MapClient & { dev: string; dev_name: string | null; port: string | null; ssid: string | null })[];
}

/** /api/network-map/layouts/{scope}: the positions people moved, shared by the team. */
export interface NetworkMapLayout {
  scope: string;
  positions: Record<string, { x: number; y: number }>;
  /** 0 when nobody has moved anything in this scope */
  revision: number;
  updated_by: number | null;
  updated_at: string | null;
}

/** /api/network-map/views: a named view of the network map, shared by the team. */
export interface NetworkMapView {
  id: string;
  name: string;
  state: Record<string, unknown>;
  owner_id: number | null;
  revision: number;
  created_at: string;
  updated_at: string;
}
