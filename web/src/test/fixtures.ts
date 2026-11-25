import type {
  AuthProvider,
  AuthProvidersResponse,
  AuthSettings,
  CollectionProgress,
  DiffResponse,
  GroupMapping,
  Hop,
  JobHistory,
  Leg,
  Me,
  PathResponse,
  RunHistory,
  SnapshotList,
  Source,
  SourceTypeSchema,
  SourceTypesResponse,
  User,
} from "../api/types";
import type {
  AssessImpactResult,
  PredictRoutesResult,
  ResolveAddressResult,
  SimulatePolicyChangeResult,
} from "../changesim/assessImpact";
import type { ResultValue } from "../results/text";

/** The result of one statement, as the server writes it: decided, or open on
 *  one missing entry. */
function decidedResult(statement: string, answer: "true" | "false", word: string): ResultValue {
  return { kind: "result", statement, answer, word, quantifier: null, condition: null, missing: [] };
}

/** A hop's `detail` and `result`: forwarded, or blocked by the cause its
 *  prose names. */
export function hop(detail: string, blocked = false): { detail: string; result: ResultValue } {
  const word = blocked ? (detail.startsWith("BLOCKED") ? `blocked${detail.slice("BLOCKED".length)}` : "blocked") : "forwarded";
  return { detail, result: decidedResult("hop-forwards", blocked ? "false" : "true", word) };
}

/** A walk's `detail` and `result`: forwarded on all candidate paths, or blocked. */
export function walk(detail: string, blocked = false): { detail: string; result: ResultValue } {
  return {
    detail,
    result: decidedResult("trace-forwards", blocked ? "false" : "true", blocked ? "blocked" : "forwarded, all candidate paths"),
  };
}

/** A simulated flow side's `detail` and `result`: permitted, or blocked by a rule. */
export function permits(detail: string, blocked = false): { detail: string; result: ResultValue } {
  return { detail, result: decidedResult("rule-permits", blocked ? "false" : "true", blocked ? `blocked by ${detail.replace(/^blocked by /, "")}` : "permitted") };
}

// Mirrors ROLE_PERMISSIONS in src/hst/app/permissions.py, sorted
// the same way the backend sorts them for the real /api/me response.
export const ME_VIEWER: Me = {
  username: "viewer1",
  role: "viewer",
  permissions: ["agent.ask", "graph.read"],
  theme: null,
};
export const ME_OPERATOR: Me = {
  username: "operator1",
  role: "operator",
  permissions: ["agent.ask", "changes.write", "cypher.run", "graph.read", "interfaces.read", "runs.manage", "sites.write"],
  theme: null,
};
export const ME_ADMIN: Me = {
  username: "admin1",
  role: "admin",
  permissions: [
    "agent.ask",
    "changes.write",
    "cypher.run",
    "graph.purge",
    "graph.read",
    "interfaces.read",
    "runs.manage",
    "settings.ai",
    "settings.auth",
    "sites.write",
    "sources.write",
    "users.manage",
  ],
  theme: null,
};

/*
 * /api/path fixtures in the shape of src/hst/path/trace.py's trace().
 */

// Single host -> host, one leg, one straight line (all hops on lane 0).
export const FIXTURE_PATH_SINGLE: PathResponse = {
  ...walk("192.168.10.44 → 8.8.8.8:443/tcp: egress via eth0.1 (0.0.0.0/0, main table)"),
  notes: [],
  hops: [
    { uid: "ep:host44", kind: "Endpoint", label: "host44", note: "src 192.168.10.44", rank: 0, lane: 0, shared: true },
    { uid: "port:sw1/1", kind: "Port", label: "eth1", note: "on sw1", rank: 1, lane: 0, shared: true },
    { uid: "dev:sw1", kind: "Device", label: "sw1", note: "", rank: 2, lane: 0, shared: true },
    { uid: "if:core1/eth0.10", kind: "Interface", label: "eth0.10", note: "gateway for 192.168.10.0/24", rank: 3, lane: 0, shared: true },
    { uid: "dev:core1", kind: "Device", label: "core1", note: "", rank: 4, lane: 0, shared: true },
    { uid: "vrf:default", kind: "VrfInstance", label: "default", note: "main table (no PBR match)", rank: 5, lane: 0, shared: false },
    { uid: "pfx:0.0.0.0/0", kind: "Prefix", label: "0.0.0.0/0", note: "static route", rank: 6, lane: 0, shared: false },
    { uid: "if:core1/eth0.1", kind: "Interface", label: "eth0.1", note: "egress", rank: 7, lane: 0, shared: false },
  ],
  legs: [
    {
      lane: 0, sources: ["192.168.10.44/32"], cidr: "0.0.0.0/0", egress: "eth0.1",
      next_hop: null, blocked: false, table: "default", src_label: "192.168.10.44",
      ...hop("egress via eth0.1"),
    },
  ],
};

// The ECMP trace has two lanes that differ only in the egress hop.
export const FIXTURE_PATH_ECMP: PathResponse = {
  ...walk("192.168.10.44 → 8.8.8.8:443/tcp: ECMP over 0.0.0.0/0 · 2 paths: eth0.1; wg0"),
  notes: [],
  hops: [
    { uid: "if:core1/eth0.10", kind: "Interface", label: "eth0.10", note: "gateway for 192.168.10.0/24", rank: 0, lane: 0, shared: true },
    { uid: "dev:core1", kind: "Device", label: "core1", note: "", rank: 1, lane: 0, shared: true },
    { uid: "vrf:default", kind: "VrfInstance", label: "default", note: "main table (no PBR match)", rank: 2, lane: 0, shared: false },
    { uid: "pfx:0.0.0.0/0#a", kind: "Prefix", label: "0.0.0.0/0", note: "static route · 2 paths", rank: 3, lane: 0, shared: false },
    { uid: "if:core1/eth0.1", kind: "Interface", label: "eth0.1", note: "egress", rank: 4, lane: 0, shared: false },
    { uid: "tun:wg0", kind: "Tunnel", label: "wg0", note: "wireguard", rank: 4, lane: 1, shared: false },
  ],
  legs: [
    {
      lane: 0, sources: ["192.168.10.44/32"], cidr: "0.0.0.0/0", egress: "eth0.1",
      next_hop: null, blocked: false, table: "default", src_label: "192.168.10.44",
      ...hop("egress via eth0.1"),
    },
    {
      lane: 1, sources: ["192.168.10.44/32"], cidr: "0.0.0.0/0", egress: "wg0",
      next_hop: null, blocked: false, table: "default", src_label: "192.168.10.44",
      ...hop("egress via wg0"),
    },
  ],
};

// The partition trace has two legs with distinct src_labels.
export const FIXTURE_PATH_PARTITION: PathResponse = {
  ...walk("192.168.10.0/24 → 8.8.8.8:443/tcp: 2 paths: 192.168.10.43/32, 192.168.10.44/31 → wg0; 192.168.10.0/24 +1 more (251 addresses) → eth0.1"),
  notes: [],
  hops: [
    { uid: "if:core1/eth0.10", kind: "Interface", label: "eth0.10", note: "gateway for 192.168.10.0/24", rank: 0, lane: 0, shared: true },
    { uid: "dev:core1", kind: "Device", label: "core1", note: "", rank: 1, lane: 0, shared: true },
    { uid: "pbr:steer-streaming", kind: "PbrPolicy", label: "steer-streaming", note: "PBR gate", rank: 2, lane: 0, shared: false },
    { uid: "vrf:table100", kind: "VrfInstance", label: "table100", note: "PBR rule 1 → table100", rank: 3, lane: 0, shared: false },
    { uid: "pfx:0.0.0.0/0#pbr", kind: "Prefix", label: "0.0.0.0/0", note: "static route", rank: 4, lane: 0, shared: false },
    { uid: "fwrb:LAN-VPN", kind: "FwRulebase", label: "LAN-VPN", note: "LAN→VPN · accept (rule 1)", rank: 5, lane: 0, shared: false },
    { uid: "tun:wg0", kind: "Tunnel", label: "wg0", note: "wireguard", rank: 6, lane: 0, shared: false },
    { uid: "vrf:default", kind: "VrfInstance", label: "default", note: "main table (no PBR match)", rank: 2, lane: 1, shared: false },
    { uid: "pfx:0.0.0.0/0#main", kind: "Prefix", label: "0.0.0.0/0", note: "static route", rank: 3, lane: 1, shared: false },
    { uid: "if:core1/eth0.1", kind: "Interface", label: "eth0.1", note: "egress", rank: 4, lane: 1, shared: false },
  ],
  legs: [
    {
      lane: 0, sources: ["192.168.10.43/32", "192.168.10.44/31"], cidr: "0.0.0.0/0",
      egress: "wg0", next_hop: null, blocked: false, table: "table100",
      src_label: "192.168.10.43/32, 192.168.10.44/31", ...hop("egress via wg0"),
    },
    {
      lane: 1, sources: ["192.168.10.0/24"], cidr: "0.0.0.0/0", egress: "eth0.1",
      next_hop: null, blocked: false, table: "default",
      src_label: "192.168.10.0/24 +1 more (251 addresses)", ...hop("egress via eth0.1"),
    },
  ],
};

// A FwRulebase gate denies the flow.
export const FIXTURE_PATH_BLOCKED: PathResponse = {
  ...walk("192.168.105.0/24 → 192.168.2.0/24:22/tcp: BLOCKED by IOT-LAN default-action", true),
  notes: ["192.168.105.0/24 via eth1.5: IOT-LAN (IOT→LAN) drop by default-action"],
  hops: [
    { uid: "if:core1/eth1.5", kind: "Interface", label: "eth1.5", note: "gateway for 192.168.105.0/24", rank: 0, lane: 0, shared: true },
    { uid: "dev:core1", kind: "Device", label: "core1", note: "", rank: 1, lane: 0, shared: true },
    { uid: "vrf:default", kind: "VrfInstance", label: "default", note: "main table (no PBR match)", rank: 2, lane: 0, shared: false },
    { uid: "pfx:192.168.2.0/24", kind: "Prefix", label: "192.168.2.0/24", note: "static route", rank: 3, lane: 0, shared: false },
    { uid: "fwrb:IOT-LAN", kind: "FwRulebase", label: "IOT-LAN", note: "IOT→LAN · drop (default-action)", rank: 4, lane: 0, shared: false },
  ],
  legs: [
    {
      lane: 0, sources: ["192.168.105.0/24"], cidr: "192.168.2.0/24", egress: null,
      next_hop: null, blocked: true, table: "default", src_label: "192.168.105.0/24",
      firewall: "IOT-LAN (IOT→LAN) drop by default-action", fw_uid: "fwrb:IOT-LAN",
      ...hop("BLOCKED by IOT-LAN default-action", true),
    },
  ],
};

// Leaf and spine: 2 ECMP splits give 4 lanes. The engine adds a hop again on
// each lane that crosses it, so border1, fw-dc and dc-core sit on lanes 0 and
// 2, border2 and its ACL on lanes 1 and 3. Lanes 0 and 2 are permitted by the
// fw-dc rulebase and delivered; lanes 1 and 3 are denied by acl-in on border2.
const LS_KIND: Record<string, string> = {
  src: "Endpoint", if: "Interface", dev: "Device", vrf: "VrfInstance", pfx: "Prefix", gate: "FwRulebase", dst: "IpAddress",
};
const LS_NOTE: Record<string, string> = {
  "gate:border2/acl-in": "deny (rule 40 iot-to-dc)",
  "gate:fw-dc/rules": "permit (rule 210 app-https)",
};
function lsHop(uid: string, rank: number, lane: number, shared: boolean): Hop {
  const kind = LS_KIND[uid.split(":")[0]];
  const label = uid === "src" ? "10.20.1.15" : uid === "dst" ? "10.40.2.20" : uid.slice(uid.indexOf(uid.includes("/") ? "/" : ":") + 1);
  return { uid, kind, label, note: LS_NOTE[uid] ?? `${label} note`, rank, lane, shared };
}
const LS_HEAD = ["src", "if:leaf1/vlan20", "dev:leaf1", "vrf:leaf1/prod", "pfx:leaf1/10.40.0.0/16"];
const LS_SPINE = (sp: string, egress: string) => [`if:leaf1/${egress}`, `if:${sp}/eth1`, `dev:${sp}`, `pfx:${sp}/10.40.0.0/16`];
const LS_B1 = ["dev:border1", "if:border1/eth9", "if:fw-dc/eth1", "dev:fw-dc", "gate:fw-dc/rules", "if:fw-dc/eth2", "if:dc-core/eth1", "dev:dc-core", "if:dc-core/vlan40", "dst"];
const LS_B2 = ["dev:border2", "gate:border2/acl-in"];
const LS_LANES = [
  [...LS_SPINE("spine1", "eth49"), "if:spine1/eth3", "if:border1/eth1", ...LS_B1],
  [...LS_SPINE("spine1", "eth49"), "if:spine1/eth4", "if:border2/eth1", ...LS_B2],
  [...LS_SPINE("spine2", "eth50"), "if:spine2/eth3", "if:border1/eth2", ...LS_B1],
  [...LS_SPINE("spine2", "eth50"), "if:spine2/eth4", "if:border2/eth2", ...LS_B2],
];
function lsLeg(lane: number): Leg {
  const blocked = lane % 2 === 1;
  return {
    lane, sources: ["10.20.1.15/32"], cidr: "10.40.0.0/16", egress: blocked ? null : "vlan40",
    next_hop: null, blocked, table: "prod", src_label: "10.20.1.15",
    ...(blocked
      ? { fw_uid: "gate:border2/acl-in", firewall: "acl-in deny rule 40", ...hop("BLOCKED by acl-in rule 40", true) }
      : { fw_uid: "gate:fw-dc/rules", delivered: true, ...hop("delivered to 10.40.2.20") }),
  };
}
export const FIXTURE_PATH_LEAF_SPINE: PathResponse = {
  ...walk("10.20.1.15 → 10.40.2.20:443/tcp: 4 paths"),
  notes: [],
  hops: [
    ...LS_HEAD.map((uid, rank) => lsHop(uid, rank, 0, true)),
    ...LS_LANES.flatMap((uids, lane) => uids.map((uid, i) => lsHop(uid, LS_HEAD.length + i, lane, false))),
  ],
  legs: [0, 1, 2, 3].map(lsLeg),
};

/*
 * Ops fixtures in the shape of sources.py's `source_types()` and `_json()`.
 */

// A trimmed unifi schema: string, int and bool fields and one secret.
export const SCHEMA_UNIFI: SourceTypeSchema = {
  type: "object",
  title: "UnifiConfig",
  properties: {
    site_code: { type: "string", title: "Site Code", default: "home" },
    source_name: { type: "string", title: "Source Name", default: "" },
    url: { type: "string", title: "Url" },
    user: { type: "string", title: "User" },
    password: { type: "string", title: "Password", format: "password", writeOnly: true },
    site: { type: "string", title: "Site", default: "default" },
    verify_ssl: { type: "boolean", title: "Verify Ssl", default: false },
  },
  required: ["url", "user", "password"],
};

// A trimmed manual schema with a `format: "multiline"` field.
export const SCHEMA_MANUAL: SourceTypeSchema = {
  type: "object",
  title: "ManualConfig",
  properties: {
    site_code: { type: "string", title: "Site Code", default: "home" },
    source_name: { type: "string", title: "Source Name", default: "" },
    devices: { type: "string", title: "Devices", format: "multiline" },
  },
  required: ["devices"],
};

export const SOURCE_TYPES: SourceTypesResponse = {
  types: [{ type: "unifi", kind: "orchestrator", schema: SCHEMA_UNIFI }],
};

export const SOURCE_UNIFI: Source = {
  name: "home-unifi",
  type: "unifi",
  kind: "orchestrator",
  config: { site_code: "home", url: "https://192.168.1.1", user: "admin", site: "default", verify_ssl: false },
  secrets: { password: true },
  enabled: true,
  updated_at: "2026-07-20T12:00:00+00:00",
};

export const SOURCES_RESPONSE: { sources: Source[] } = { sources: [SOURCE_UNIFI] };

// Two finished runs.
export const RUN_HISTORY_IDLE: RunHistory = {
  sources: ["home-unifi", "reasoner"],
  runs: [
    {
      id: 2,
      source: "reasoner",
      status: "ok",
      started_at: "2026-07-23T10:00:00+00:00",
      finished_at: "2026-07-23T10:00:05+00:00",
      detail: "adjacency: 3, l3-reachability: 12",
    },
    {
      id: 1,
      source: "home-unifi",
      status: "ok",
      started_at: "2026-07-22T09:00:00+00:00",
      finished_at: "2026-07-22T09:01:10+00:00",
      detail: "nodes 40 (+2, -0) · rels 88 (+4, -0) · changes 6",
    },
  ],
};

export const RUN_HISTORY_RUNNING: RunHistory = {
  sources: ["home-unifi", "reasoner"],
  runs: [
    {
      id: 3,
      source: "home-unifi",
      status: "running",
      started_at: "2026-07-23T11:00:00+00:00",
      finished_at: null,
      detail: "",
    },
    ...RUN_HISTORY_IDLE.runs,
  ],
};

// A cycle is one run row over 2 sources.
function bar(source: string, completed: number, total: number): CollectionProgress {
  return {
    source,
    state: "collecting",
    phase: "Fetching devices",
    completed,
    total,
    phase_eta_s: null,
    started_at_ms: 1_753_268_400_000,
    updated_at_ms: Date.now(),
  } as CollectionProgress;
}

export const RUN_HISTORY_CYCLE: RunHistory = {
  sources: ["home-unifi", "nxos-edge", "reasoner"],
  runs: [
    {
      id: 7,
      source: "cycle",
      status: "running",
      started_at: "2026-07-23T11:00:00+00:00",
      finished_at: null,
      detail: "",
      progress: [bar("nxos-edge", 12, 40), bar("iosxe-core", 3, 8)],
    },
    ...RUN_HISTORY_IDLE.runs,
  ],
};

// The maintenance queue as RunsPage reads it: one finished sweep, one that
// failed and gave up, and one waiting its turn.
export const JOB_HISTORY_IDLE: JobHistory = {
  jobs: [
    {
      id: 3,
      kind: "maintenance.prune_graph",
      source: null,
      device: null,
      state: "dead",
      attempt: 4,
      max_attempts: 4,
      enqueued_at: "2026-07-23T10:00:00+00:00",
      started_at: "2026-07-23T10:00:00+00:00",
      finished_at: "2026-07-23T10:00:02+00:00",
      not_before: "2026-07-23T10:00:00+00:00",
      duration_s: 2.4,
      detail: "RuntimeError: twin unreachable",
      triggered_by: "scheduler",
    },
    {
      id: 2,
      kind: "maintenance.purge_sessions",
      source: null,
      device: null,
      state: "ok",
      attempt: 1,
      max_attempts: 4,
      enqueued_at: "2026-07-23T09:00:00+00:00",
      started_at: "2026-07-23T09:00:00+00:00",
      finished_at: "2026-07-23T09:00:00.120000+00:00",
      not_before: "2026-07-23T09:00:00+00:00",
      duration_s: 0.12,
      detail: "deleted 3 expired session(s) and 1 abandoned login attempt(s)",
      triggered_by: "scheduler",
    },
  ],
  depth: { ok: 1, dead: 1 },
};

export const JOB_HISTORY_PENDING: JobHistory = {
  jobs: [
    {
      id: 4,
      kind: "maintenance.purge_login_events",
      source: null,
      device: null,
      state: "queued",
      attempt: 0,
      max_attempts: 4,
      enqueued_at: "2026-07-23T11:00:00+00:00",
      started_at: null,
      finished_at: null,
      not_before: "2026-07-23T11:00:00+00:00",
      duration_s: null,
      detail: "",
      triggered_by: "scheduler",
    },
    ...JOB_HISTORY_IDLE.jobs,
  ],
  depth: { queued: 1, ok: 1, dead: 1 },
};

export const USER_ADMIN_ROW: User = {
  id: 1,
  username: "admin1",
  role: "admin",
  role_source: "local",
  has_password: true,
  identities: [],
  disabled: false,
  created_at: "2026-01-01T00:00:00+00:00",
};

export const USER_VIEWER_ROW: User = {
  id: 2,
  username: "viewer1",
  role: "viewer",
  role_source: "local",
  has_password: true,
  identities: [],
  disabled: false,
  created_at: "2026-01-02T00:00:00+00:00",
};

export const USERS_RESPONSE: { users: User[] } = { users: [USER_ADMIN_ROW, USER_VIEWER_ROW] };

// A mapped row and an overridden row of SSO-provisioned users.
export const USER_MAPPED_ROW: User = {
  id: 3,
  username: "okta.jsmith",
  role: "operator",
  role_source: "mapped",
  has_password: false,
  identities: ["okta"],
  disabled: false,
  created_at: "2026-02-01T00:00:00+00:00",
};

export const USER_OVERRIDDEN_ROW: User = {
  id: 4,
  username: "okta.awong",
  role: "admin",
  role_source: "local",
  has_password: false,
  identities: ["okta"],
  disabled: false,
  created_at: "2026-02-02T00:00:00+00:00",
};

// --- SSO admin fixtures -------------------------------------------------------

export const AUTH_PROVIDERS_PUBLIC: AuthProvidersResponse = {
  providers: [{ name: "okta", kind: "oidc", label: "Okta" }],
  local_login_enabled: true,
};

export const AUTH_SETTINGS: AuthSettings = { local_login_enabled: true };

export const AUTH_PROVIDER_OIDC: AuthProvider = {
  id: 1,
  name: "okta",
  kind: "oidc",
  enabled: true,
  config: {
    issuer: "https://example.okta.com",
    client_id: "abc123",
    groups_claim: "groups",
    default_role: "viewer",
    label: "Okta",
  },
  has_secret: true,
  created_at: "2026-07-01T00:00:00+00:00",
  updated_at: "2026-07-01T00:00:00+00:00",
  redirect_uri: "https://hst.example.net/api/auth/okta/callback",
};

export const AUTH_PROVIDER_SAML: AuthProvider = {
  id: 2,
  name: "adfs",
  kind: "saml",
  enabled: false,
  config: {
    idp_metadata_url: "https://adfs.example.com/metadata.xml",
    username_attr: "",
    groups_attr: "",
    default_role: "none",
    label: "",
  },
  has_secret: false,
  created_at: "2026-07-02T00:00:00+00:00",
  updated_at: "2026-07-02T00:00:00+00:00",
  sp_entity_id: "https://hst.example.net/api/auth/adfs/metadata",
  sp_acs_url: "https://hst.example.net/api/auth/adfs/acs",
};

export const AUTH_PROVIDERS_ADMIN: AuthProvider[] = [AUTH_PROVIDER_OIDC, AUTH_PROVIDER_SAML];

export const GROUP_MAPPINGS_OKTA: GroupMapping[] = [{ group_name: "network-admins", role: "admin" }];

// --- Time travel fixtures ----------------------------------------------------

// GET /api/snapshots sorts the snapshots newest first.
export const FIXTURE_SNAPSHOTS: SnapshotList = {
  snapshots: [
    {
      id: "1724236800000",
      ts_ms: 1724236800000,
      created: "2026-08-21T10:00:00+00:00",
      nodes: 3745,
      rels: 33586,
      sources_fresh: ["vyos"],
      sources_carried: ["unifi"],
      sources_failed: [],
      degraded: false,
      kind: "full",
      parent: 1724000000000,
    },
    {
      id: "1724000000000",
      ts_ms: 1724000000000,
      created: "2026-08-18T15:33:20+00:00",
      nodes: 3700,
      rels: 33200,
      sources_fresh: ["vyos", "unifi"],
      sources_carried: [],
      sources_failed: ["meraki"],
      degraded: true,
      kind: "full",
      parent: null,
    },
  ],
  current: 1724236800000,
  truncated: false,
};

// The diff follows the example of the diff.py route.
export const FIXTURE_DIFF: DiffResponse = {
  a: 1724000000000,
  b: 1724236800000,
  counts: {
    nodes: { added: 1, removed: 0, changed: 1 },
    rels: { added: 0, removed: 1, changed: 0 },
  },
  nodes: {
    added: [{ uid: "dev:x", label: "Device", name: "x" }],
    removed: [],
    changed: [{ uid: "dev:y", label: "Device", name: "y", changes: { role: ["router", "firewall"] } }],
  },
  rels: {
    added: [],
    removed: [{ type: "ON", start: "if:a", end: "dev:x" }],
    changed: [],
  },
  truncated: false,
};

// --- Change simulation fixtures ----------------------------------------------

// Modeled on assess() in src/hst/app/routes/impact.py: the device
// identity and every bucket, with one item each.
export const FIXTURE_ASSESS_IMPACT: AssessImpactResult = {
  snapshot: "1724236800000",
  device: {
    uid: "dev:leaf101",
    hostname: "leaf101",
    role: "leaf",
    software_version: "17.9.1",
    platform: "cat9k",
    vendor: "cisco",
    model: "C9300-48P",
  },
  single_homed_prefixes: {
    count: 1,
    items: [{ uid: "prefix:10.0.1.0/24", cidr: "10.0.1.0/24", kind: "connected", l3dom: "default" }],
    truncated: false,
  },
  single_homed_endpoints: {
    count: 1,
    items: [{ uid: "ep:aabb", name: "host9", kind: "server" }],
    truncated: false,
  },
  gateway_prefixes: {
    count: 1,
    items: [
      { uid: "prefix:10.0.1.0/24", cidr: "10.0.1.0/24", kind: "connected", l3dom: "default", other_devices: [] },
    ],
    truncated: false,
  },
  attached_endpoints: {
    count: 1,
    items: [{ uid: "ep:aabb", name: "host9", kind: "server", other_devices: [] }],
    truncated: false,
  },
  redundancy_groups: {
    count: 1,
    items: [
      {
        uid: "rg:1",
        kind: "hsrp",
        name: "rg1",
        role: "active",
        other_members: [{ uid: "dev:leaf102", hostname: "leaf102" }],
        has_other_members: true,
      },
    ],
    truncated: false,
  },
  interfaces: { count: 1, items: [{ uid: "if:1", name: "Gi1/0/1", kind: "physical" }], truncated: false },
  tunnels: { count: 0, items: [], truncated: false },
  bgp_sessions: {
    count: 1,
    items: [
      {
        uid: "bgp:1",
        local_ip: "10.0.0.1",
        peer_ip: "10.0.0.2",
        peer_asn: 65001,
        kind: "ebgp",
        state: "established",
      },
    ],
    truncated: false,
  },
  fhrp_groups: {
    count: 1,
    items: [
      {
        uid: "fhrp:1",
        kind: "hsrp",
        group_id: 1,
        vip: "10.0.1.1",
        interfaces: ["Gi1/0/1"],
        other_devices: ["dev:leaf102"],
      },
    ],
    truncated: false,
  },
};

export const FIXTURE_ASSESS_IMPACT_JSON = JSON.stringify(FIXTURE_ASSESS_IMPACT);

// The resolve_address payload has one address and its five sections.
export const FIXTURE_RESOLVE_ADDRESS: ResolveAddressResult = {
  address: "192.168.2.35",
  snapshot: "1724236800000",
  limit_per_section: 10,
  ip_nodes: [
    { uid: "ip:bd:vlan20:192.168.2.35", anchor: "bd:vlan20", l3dom: "default", af: 4 },
  ],
  endpoints: [
    {
      uid: "ep:aabbccddeeff",
      mac: "aa:bb:cc:dd:ee:ff",
      kind: "server",
      name: "host9",
      ip_uid: "ip:bd:vlan20:192.168.2.35",
      anchor: "bd:vlan20",
      attached: [{ uid: "port:leaf101:Gi1/0/1", name: "Gi1/0/1", ssid: null, kind: "Port" }],
      bridge_domains: [{ uid: "bd:vlan20", name: "vlan20" }],
    },
  ],
  interfaces: [
    {
      uid: "if:leaf101:Vlan20",
      name: "Vlan20",
      kind: "svi",
      ip_uid: "ip:bd:vlan20:192.168.2.35",
      anchor: "bd:vlan20",
      device_uid: "dev:leaf101",
      device_hostname: "leaf101",
    },
  ],
  bgp_sessions: [
    {
      uid: "bgp:leaf101:192.168.2.35",
      peer_ip: "192.168.2.35",
      local_asn: 65000,
      peer_asn: 65001,
      import_policy_name: "FROM-EDGE",
      import_policy_kind: "route-map",
      export_policy_name: "TO-EDGE",
      export_policy_kind: "route-map",
      process_uid: "rp:leaf101:bgp",
      process_proto: "bgp",
      process_asn: 65000,
      vrf_uid: "vrf:leaf101:default",
      vrf_name: "default",
    },
  ],
  next_hop_routes: [],
};

export const FIXTURE_RESOLVE_ADDRESS_JSON = JSON.stringify(FIXTURE_RESOLVE_ADDRESS);

// The predict_routes payload groups the predicted rows per VRF.
export const FIXTURE_PREDICT_ROUTES: PredictRoutesResult = {
  scope: "dev:leaf101",
  scope_kind: "device",
  snapshot: "1724236800000",
  row_limit_per_vrf: 10,
  row_count: 2,
  truncated: false,
  vrfs: [
    {
      context_uid: "vrf:leaf101:default",
      row_count: 2,
      truncated: false,
      rows: [
        {
          context_uid: "vrf:leaf101:default",
          prefix: "10.0.1.0/24",
          next_hop: "10.0.0.2",
          protocol: "bgp",
          metric: 0,
          local_pref: 100,
          med: 0,
          weight: 0,
          as_path: [65001],
          origin: "igp",
          origin_mechanism: "originated",
          session_protocol: "ebgp",
          admin: 20,
          communities: ["65000:100"],
          originator_ip: null,
          cluster_list: [],
          tag: null,
        },
        {
          context_uid: "vrf:leaf101:default",
          prefix: "10.0.2.0/24",
          next_hop: "10.0.0.6",
          protocol: "bgp",
          metric: 0,
          local_pref: 100,
          med: 0,
          weight: 0,
          as_path: [65002, 65003],
          origin: "igp",
          origin_mechanism: "learned",
          session_protocol: "ebgp",
          admin: 20,
          communities: [],
          originator_ip: null,
          cluster_list: [],
          tag: null,
        },
      ],
    },
  ],
  model_errors: [
    {
      kind: "unpaired-bgp-session",
      detail: "a peering had no far-end session node in the snapshot, so prefixes behind it are missing",
      subject: "bgp:leaf101:10.0.0.10",
    },
  ],
};

export const FIXTURE_PREDICT_ROUTES_JSON = JSON.stringify(FIXTURE_PREDICT_ROUTES);

// Modeled on simulate_change in src/hst/app/fw_overlay_read.py: the per-flow
// result comparison, and the routing follow-on as a before-and-after routing
// table computed from the graph's own route edges. The two next hops of
// 10.10.10.1/32 are both denied and the snapshot holds no BgpSession for either.
export const FIXTURE_SIMULATE_POLICY_CHANGE: SimulatePolicyChangeResult = {
  snapshot: "1724236800000",
  intents: [
    {
      kind: "fw_rule.add",
      params: {
        rulebase: "fw:core1:LAN",
        position: 10,
        action: "drop",
        source: "any",
        destination: ["192.168.2.35", "192.168.2.36"],
      },
    },
  ],
  flow_count: 2,
  results_changed: 1,
  path_count_before: 4,
  path_count_after: 4,
  paths_blocked_before: 0,
  paths_blocked_after: 2,
  paths_changed: 2,
  changed_devices: ["dev:core1"],
  flows: [
    {
      flow: { src: "192.168.2.35", dst: "10.10.10.1/32", port: null, proto: "tcp" },
      before: {
        ...permits("permitted"),
        indeterminate: false,
        blocked: false,
        decided_by: [],
        dnat: [],
        snat: [],
        warnings: [],
      },
      after: {
        ...permits("blocked by LAN policy rule 10", true),
        indeterminate: false,
        blocked: true,
        decided_by: ["LAN policy (dev:core1) drop by rule 10"],
        dnat: [],
        snat: [],
        warnings: [],
      },
      result_changed: true,
      blocked_changed: true,
      crosses_a_changed_device: true,
      // three paths, two of them the equal-cost pair to 10.10.10.1/32
      paths: {
        group_count: 2,
        truncated: false,
        path_count_before: 3,
        path_count_after: 3,
        blocked_before: 0,
        blocked_after: 2,
        indeterminate_after: 0,
        changed: 2,
        groups: [
          {
            path_count: 2,
            destinations: ["10.10.10.1/32"],
            destination_count: 1,
            next_hops: ["10.0.0.1", "10.0.0.2"],
            next_hop_count: 2,
            egress: "eth0",
            before: {
              blocked: false,
              indeterminate: false,
              decided_by: "LAN policy (LAN>WAN) accept by default-action",
              rulebase: "fw:core1:LAN",
              ...hop("egress via eth0"),
            },
            after: {
              blocked: true,
              indeterminate: false,
              decided_by: "LAN policy (LAN>WAN) drop by rule 10",
              rulebase: "fw:core1:LAN",
              ...hop("BLOCKED by LAN policy rule 10", true),
            },
            changed: true,
            sample_truncated: false,
          },
          {
            path_count: 1,
            destinations: ["192.168.2.0/24"],
            destination_count: 1,
            next_hops: [],
            next_hop_count: 0,
            egress: "eth1",
            before: {
              blocked: false,
              indeterminate: false,
              decided_by: "INTRA (LAN>LAN) accept by rule 3",
              rulebase: "fw:core1:INTRA",
              ...hop("egress via eth1"),
            },
            after: {
              blocked: false,
              indeterminate: false,
              decided_by: "INTRA (LAN>LAN) accept by rule 3",
              rulebase: "fw:core1:INTRA",
              ...hop("egress via eth1"),
            },
            changed: false,
            sample_truncated: false,
            note: "decided by fw:core1:INTRA, which this change does not alter",
          },
        ],
      },
    },
    {
      flow: { src: "192.168.2.10", dst: "192.168.2.35", port: null, proto: "tcp" },
      before: {
        ...permits("permitted"),
        indeterminate: false,
        blocked: false,
        decided_by: [],
        dnat: [],
        snat: [],
        warnings: [],
      },
      after: {
        ...permits("permitted"),
        indeterminate: false,
        blocked: false,
        decided_by: [],
        dnat: [],
        snat: [],
        warnings: [],
      },
      result_changed: false,
      blocked_changed: false,
      crosses_a_changed_device: false,
      paths: {
        group_count: 1,
        truncated: false,
        path_count_before: 1,
        path_count_after: 1,
        blocked_before: 0,
        blocked_after: 0,
        indeterminate_after: 0,
        changed: 0,
        groups: [
          {
            path_count: 1,
            destinations: ["192.168.2.0/24"],
            destination_count: 1,
            next_hops: [],
            next_hop_count: 0,
            egress: "eth1",
            before: {
              blocked: false,
              indeterminate: false,
              decided_by: null,
              rulebase: null,
              ...hop("egress via eth1"),
            },
            after: {
              blocked: false,
              indeterminate: false,
              decided_by: null,
              rulebase: null,
              ...hop("egress via eth1"),
            },
            changed: false,
            sample_truncated: false,
            note: "no rulebase decided this path in the snapshot, so no rulebase this change alters governs it",
          },
        ],
      },
      model_error: {
        kind: "flow-does-not-cross-the-changed-device",
        detail: "the flow crosses none of the devices this change set alters (dev:core1)",
        subject: "192.168.2.10 -> 192.168.2.35",
      },
    },
  ],
  routing_consequence: {
    headline:
      "1 prefix(es) across 1 VRF(s) lose a recorded next hop, 1 of them every next hop the snapshot records",
    basis: "the route edges the snapshot records",
    direction_rule:
      "denying traffic to an address removes it as a next hop for every recorded route",
    denied_addresses: { traffic_to: ["192.168.2.35", "192.168.2.36"], traffic_from: [] },
    next_hop_withdrawal: {
      prefix_count: 1,
      prefixes_with_no_next_hop_left: 1,
      withdrawn_route_edge_count: 2,
      truncated: false,
      vrfs: [
        {
          context_uid: "vrf:dev:x:vyos:core1:default",
          prefix_count: 1,
          prefixes_with_no_next_hop_left: 1,
          truncated: false,
          prefixes: [
            {
              prefix: "10.10.10.1/32",
              no_next_hop_left: true,
              next_hops_before: [
                {
                  next_hop: "192.168.2.35",
                  kind: "LEARNED_ROUTE",
                  protocol: "bgp",
                  interface: "eth0",
                  metric: 20,
                  withdrawn_because: "the change denies traffic to this next hop",
                },
                {
                  next_hop: "192.168.2.36",
                  kind: "LEARNED_ROUTE",
                  protocol: "bgp",
                  interface: "eth1",
                  metric: 20,
                  withdrawn_because: "the change denies traffic to this next hop",
                },
              ],
              next_hops_after: [],
              withdrawn_next_hops: [
                {
                  next_hop: "192.168.2.35",
                  kind: "LEARNED_ROUTE",
                  protocol: "bgp",
                  interface: "eth0",
                  metric: 20,
                  withdrawn_because: "the change denies traffic to this next hop",
                },
              ],
            },
          ],
        },
      ],
    },
    evaluation: "address-dependency",
    bgp_sessions_to_a_denied_address: [
      {
        uid: "bgp:core1:1",
        peer_ip: "192.168.2.35",
        peer_asn: 65002,
        local_asn: 65001,
        process_uid: "rp:core1",
        context_uid: "vrf:dev:x:vyos:core1:default",
      },
    ],
    bgp_sessions_to_a_denied_address_note:
      "this BGP session peers through an address the change set denies; that is an address " +
      "dependency, not a prediction that the session goes down. Whether it actually does needs " +
      "a context-scoped control-plane evaluation this address match does not perform",
    implied_intents: [],
    predicted_prefixes_withdrawn: [],
    predicted_withdrawn_count: 0,
  },
  model_errors: [
    {
      kind: "flow-does-not-cross-the-changed-device",
      detail: "the flow crosses none of the devices this change set alters (dev:core1)",
      subject: "192.168.2.10 -> 192.168.2.35",
    },
  ],
};

export const FIXTURE_SIMULATE_POLICY_CHANGE_JSON = JSON.stringify(FIXTURE_SIMULATE_POLICY_CHANGE);

// --- Catalogue envelopes (src/hst/twin_tools/envelope.py) ---------------------

/** A catalogue tool's envelope around `result`, computed from run `snapshot`. */
export function catalogueEnvelope(tool: string, result: Record<string, unknown>, snapshot = "1724236800000") {
  return {
    snapshot: {
      id: snapshot,
      collection_ts: Number(snapshot),
      selector: "latest",
      manifest_sha256: null,
      approximate: true,
      run: { snapshot, degraded: false },
    },
    provenance: {
      tool,
      tool_version: 1,
      engine: null,
      engine_function: null,
      queries: [],
      args_sha256: "0".repeat(64),
      actor: null,
      computed_at: "2024-08-21T10:00:00Z",
    },
    evidence: {
      result: { kind: "record", word: "recorded in the snapshot", missing: [] },
      unknowns: [],
      gaps: [],
      gaps_truncated: false,
    },
    page: { next_cursor: null, truncated: false, total: null, limit: null },
    result,
    warnings: [],
  };
}

const { snapshot: _impactRun, device: _impactDevice, model_errors: _impactErrors, ...IMPACT_BUCKETS } =
  FIXTURE_ASSESS_IMPACT;

// Modeled on impact_assess in src/hst/twin_tools/impact.py, subject device:
// the same device and buckets as FIXTURE_ASSESS_IMPACT.
export const FIXTURE_IMPACT_ASSESS_ENVELOPE = catalogueEnvelope("impact_assess", {
  subject: "device",
  device_uid: FIXTURE_ASSESS_IMPACT.device.uid,
  device: FIXTURE_ASSESS_IMPACT.device,
  buckets: IMPACT_BUCKETS,
});

export const FIXTURE_IMPACT_ASSESS_JSON = JSON.stringify(FIXTURE_IMPACT_ASSESS_ENVELOPE);

const ADDRESS_SECTIONS = ["ip_nodes", "endpoints", "interfaces", "bgp_sessions", "next_hop_routes"] as const;

// Modeled on inventory_resolve in src/hst/twin_tools/inventory.py, kind
// address: the same address and sections as FIXTURE_RESOLVE_ADDRESS.
export const FIXTURE_INVENTORY_RESOLVE_ENVELOPE = catalogueEnvelope("inventory_resolve", {
  kind: "address",
  address: FIXTURE_RESOLVE_ADDRESS.address,
  sections: Object.fromEntries(
    ADDRESS_SECTIONS.map((key) => [key, { rows: FIXTURE_RESOLVE_ADDRESS[key], truncated: false }]),
  ),
});

export const FIXTURE_INVENTORY_RESOLVE_JSON = JSON.stringify(FIXTURE_INVENTORY_RESOLVE_ENVELOPE);

// Modeled on routing_predict_routes in src/hst/twin_tools/routing.py: the
// same VRF and rows as FIXTURE_PREDICT_ROUTES, one VRF per page item.
export const FIXTURE_ROUTING_PREDICT_ROUTES_JSON = JSON.stringify(
  catalogueEnvelope("routing_predict_routes", {
    scope: FIXTURE_PREDICT_ROUTES.scope,
    scope_kind: FIXTURE_PREDICT_ROUTES.scope_kind,
    vrf_count: FIXTURE_PREDICT_ROUTES.vrfs.length,
    vrfs: FIXTURE_PREDICT_ROUTES.vrfs.map((vrf) => ({
      context_uid: vrf.context_uid,
      row_count: vrf.row_count,
      rows: vrf.rows,
      rows_truncated: vrf.truncated,
      evidence: { result: { kind: "record", word: "computed from configuration; not observed", missing: [] }, basis: "computed" },
      added: null,
      removed: null,
      changed: null,
    })),
    model_scope: "BGP-only propagation to a fixed point",
    model_errors: FIXTURE_PREDICT_ROUTES.model_errors,
  }),
);

const { snapshot: _policyRun, ...POLICY_RESULT } = FIXTURE_SIMULATE_POLICY_CHANGE;

// Modeled on change_simulate in src/hst/twin_tools/change.py: the same
// simulation as FIXTURE_SIMULATE_POLICY_CHANGE, as the envelope's result.
export const FIXTURE_CHANGE_SIMULATE_JSON = JSON.stringify(
  catalogueEnvelope("change_simulate", POLICY_RESULT as unknown as Record<string, unknown>),
);
