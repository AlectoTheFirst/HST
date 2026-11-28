/** The types mirror src/hst/app/inventory/contracts.py. */

import { api } from "./client";
import type { SiteBlock } from "./types";

export const CONTRACT_VERSION = 1;
export const API_PREFIX = "/inventory";
export const INVENTORY_WRITE = "inventory.write";
export const MAX_PAGE_LIMIT = 200;
export const MAX_SELECTION = 1000;
export const MAX_BULK_ROWS = 5000;

// --- enums (string unions matching the Python StrEnums) ---------------------

export type ErrorCode =
  | "inventory_changed"
  | "normalization_migrated"
  | "stale_revision"
  | "preview_expired"
  | "forbidden"
  | "not_found"
  | "validation"
  | "observed_store_unavailable"
  | "conflict"
  | "idempotency_conflict";

export type PreviewOperation =
  | "place_devices"
  | "assign_target_profile"
  | "edit_profile"
  | "rotate_credential"
  | "delete_site"
  | "delete_connection"
  | "delete_target"
  | "replace_target"
  | "edit_routing_members"
  | "archive_devices"
  | "restore_devices";

export const PREVIEW_OPERATIONS: readonly PreviewOperation[] = [
  "place_devices",
  "assign_target_profile",
  "edit_profile",
  "rotate_credential",
  "delete_site",
  "delete_connection",
  "delete_target",
  "replace_target",
  "edit_routing_members",
  "archive_devices",
  "restore_devices",
];

export type Lifecycle =
  | "active"
  | "missing"
  | "archived";

export const LIFECYCLES: readonly Lifecycle[] = [
  "active",
  "missing",
  "archived",
];

export type LifecycleAction =
  | "archive"
  | "unarchive";

export type TargetKind =
  | "direct"
  | "controller"
  | "implicit";

export type ConnectionKind =
  | "direct"
  | "controller";

export type ObservationState =
  | "current"
  | "stale"
  | "absent";

export type Authority =
  | "complete"
  | "partial";

export type PlacementMode =
  | "auto"
  | "assigned"
  | "unplaced";

export type PlacementOrigin =
  | "manual"
  | "migrated"
  | "onboarding";

export type PlacementState =
  | "assigned"
  | "auto"
  | "unplaced"
  | "conflict"
  | "stale"
  | "pending";

export const PLACEMENT_STATES: readonly PlacementState[] = [
  "assigned",
  "auto",
  "unplaced",
  "conflict",
  "stale",
  "pending",
];

export type PlacementBasis =
  | "assigned"
  | "bound_locations"
  | "onboarding"
  | "none";

export type CollectionState =
  | "current"
  | "stale"
  | "partial"
  | "failed"
  | "never"
  | "manual";

export const COLLECTION_STATES: readonly CollectionState[] = [
  "current",
  "stale",
  "partial",
  "failed",
  "never",
  "manual",
];

export type PublicationState =
  | "staged"
  | "published"
  | "applied"
  | "aborted";

export type OutboxKind =
  | "publication_reconcile"
  | "job_enqueue";

export type OutboxState =
  | "pending"
  | "running"
  | "done"
  | "failed";

export type ActivationState =
  | "inactive"
  | "backfill_ready"
  | "active";

export type FieldCategory =
  | "profile"
  | "credential"
  | "connection"
  | "target"
  | "internal"
  | "legacy_normalization";

export type IdentitySensitivity =
  | "none"
  | "label"
  | "scope"
  | "identity";

export type SortField =
  | "name"
  | "platform"
  | "site"
  | "last_success"
  | "collection_state";

export const SORT_FIELDS: readonly SortField[] = [
  "name",
  "platform",
  "site",
  "last_success",
  "collection_state",
];

export type SortDirection =
  | "asc"
  | "desc";

export type SiteSort =
  | "code"
  | "name"
  | "devices";

export type LocationState =
  | "all"
  | "mapped"
  | "unmapped"
  | "suggested";

export type BulkRowStatus =
  | "change"
  | "unchanged"
  | "error";

export type RouteTargetDirection =
  | "import"
  | "export";

export type ProfileOrigin =
  | "target"
  | "connection"
  | "none";

export type PreviewMemberKind =
  | "device"
  | "target"
  | "connection"
  | "profile"
  | "credential"
  | "site"
  | "routing_group";

export type ApplyStatus =
  | "applied"
  | "reused";

// --- models -------------------------------------------------------------------

export interface ErrorResponse {
  error: string;
  code: ErrorCode;
  current_revision: number | null;
  references: string[];
  detail: Record<string, unknown> | null;
}

export interface Generation {
  snapshot_key: string | null;
  intent_generation: number;
  inventory_sync_pending: boolean;
}

export interface ListCursor {
  snapshot_key: string | null;
  intent_generation: number;
  sort: SortField;
  direction: SortDirection;
  filter_digest: string;
  last_value: string | null;
  last_id: string;
}

export interface DeviceListQuery {
  q?: string | null;
  site_id?: string[];
  connection_id?: string[];
  platform?: string[];
  collection_state?: CollectionState[];
  placement_state?: PlacementState[];
  lifecycle?: Lifecycle[];
  sort?: SortField;
  direction?: SortDirection;
  limit?: number;
  cursor?: string | null;
  view_id?: string | null;
}

export interface ObservingConnection {
  connection_id: string;
  source_key: string;
  display_name: string;
  target_id: string;
  target_host: string;
  observation_state: ObservationState;
  authority: Authority;
  last_success_at: string | null;
}

export interface DeviceSummary {
  id: string;
  graph_uid: string;
  hostname: string;
  platform: string;
  management_address: string;
  lifecycle: Lifecycle;
  revision: number;
  collection_state: CollectionState;
  last_success_at: string | null;
  site_id: string | null;
  site_code: string | null;
  placement_state: PlacementState;
  connections: ObservingConnection[];
  latest_snapshot_key: string | null;
  first_seen: string;
  last_seen: string;
}

export interface DevicePage {
  items: DeviceSummary[];
  next_cursor: string | null;
  generation: Generation;
}

export interface ContributingObservation {
  target_id: string;
  connection_id: string;
  location_id: string | null;
  location_name: string;
  site_id: string | null;
  site_code: string | null;
  bound: boolean;
  state: ObservationState;
  authority: Authority;
}

export interface PlacementResponse {
  mode: PlacementMode;
  desired_site_id: string | null;
  desired_site_code: string | null;
  basis: PlacementBasis;
  contributing: ContributingObservation[];
  conflict: boolean;
  stale: boolean;
  published_site_id: string | null;
  published_site_code: string | null;
  published_snapshot_key: string | null;
  desired_revision: number;
  applied_revision: number;
  pending: boolean;
  origin: PlacementOrigin;
  actor_id: string | null;
  updated_at: string | null;
}

export interface ObservationView {
  target_id: string;
  connection_id: string;
  source_key: string;
  host: string;
  kind: TargetKind;
  reported_location_id: string | null;
  reported_location_name: string;
  last_success_at: string | null;
  last_seen_snapshot_key: string | null;
  state: ObservationState;
  authority: Authority;
  notes: Record<string, unknown> | null;
}

export interface RelatedEntity {
  uid: string;
  label: string;
  relation: string;
  name: string;
}

export interface TargetCollectionSummary {
  target_id: string;
  connection_id: string;
  enabled: boolean;
  profile_id: string | null;
  profile_revision: number | null;
  profile_origin: ProfileOrigin;
  last_attempt_at: string | null;
  last_success_at: string | null;
  consecutive_failures: number;
  last_error: string;
}

export interface DeviceDetail {
  summary: DeviceSummary;
  placement: PlacementResponse;
  observations: ObservationView[];
  related: RelatedEntity[];
  collection: TargetCollectionSummary[] | null;
  generation: Generation;
}

export interface RoutingGroupRef {
  group_id: string;
  display_name: string;
  updated_at: string;
}

export interface RouteTargetView {
  value: string;
  direction: RouteTargetDirection;
}

export interface RoutingContextView {
  authority?: string | null;
  instance_uid?: string | null;
  vsid?: number | null;
  enterprise_name?: string | null;
  derived_domains?: string[];
  context_uid: string;
  kind: string;
  owner_uid: string;
  identifier: string;
  management_domain: string | null;
  enterprise: string | null;
  segment: string | null;
  route_targets: RouteTargetView[];
  declared_domain: string | null;
  membership_basis: string;
  user_groups: RoutingGroupRef[];
}

export interface DeviceRoutingQuery {
  snapshot_key?: string | null;
}

export interface DeviceRoutingResponse {
  device_id: string;
  snapshot_key: string;
  contexts: RoutingContextView[];
  annotations_as_of: string | null;
}

export interface EventView {
  id: number;
  entity_type: string;
  entity_id: string;
  actor_id: string | null;
  actor_name: string | null;
  action: string;
  at: string;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
  request_id: string | null;
  snapshot_key: string | null;
}

export interface PageQuery {
  cursor?: string | null;
  limit?: number;
}

export interface EventPage {
  items: EventView[];
  next_cursor: string | null;
}

export interface PlacementPatch {
  mode: PlacementMode;
  site_id?: string | null;
  expected_revision: number;
}

export interface LifecyclePatch {
  action: LifecycleAction;
  expected_revision: number;
}

export interface CollectRequest {
  target_ids: string[];
}

export interface JobRef {
  job_id: number;
  target_id: string;
  source_key: string;
  host: string;
}

export interface SkippedTarget {
  target_id: string;
  reason: string;
}

export interface CollectResponse {
  jobs: JobRef[];
  skipped: SkippedTarget[];
}

export interface ConnectionListQuery {
  kind?: ConnectionKind | null;
  collector_type?: string | null;
}

export interface ConnectionHealth {
  state: CollectionState;
  last_success_at: string | null;
  last_attempt_at: string | null;
  failing_targets: number;
  target_count: number;
  device_count: number;
}

export interface ConnectionView {
  id: string;
  name: string;
  display_name: string;
  collector_type: string;
  kind: ConnectionKind;
  enabled: boolean;
  config: Record<string, unknown>;
  profile_id: string | null;
  revision: number;
  frozen_normalization: Record<string, unknown> | null;
  health: ConnectionHealth;
  created_at: string;
  updated_at: string;
  // set by a create or an edit when another controller connection shares its routing scope
  warnings?: string[];
}

export interface ConnectionCreate {
  name: string;
  display_name?: string;
  collector_type: string;
  config?: Record<string, unknown>;
  profile_id?: string | null;
  enabled?: boolean;
}

export interface ConnectionPatch {
  display_name?: string | null;
  config?: Record<string, unknown> | null;
  profile_id?: string | null;
  clear_profile?: boolean;
  enabled?: boolean | null;
  clear_jump_host_keys?: boolean;
  /** The map holds every secret of the bound credential for an edit of the endpoint or of the TLS check. */
  secrets?: Record<string, string>;
  expected_revision: number;
}

export interface TargetView {
  id: string;
  connection_id: string;
  source_key: string;
  host: string;
  port: number | null;
  kind: TargetKind;
  enabled: boolean;
  host_key_pinned: boolean;
  profile_id: string | null;
  endpoint_config?: Record<string, unknown>;
  onboarding_site_id: string | null;
  legacy_device_id: string | null;
  revision: number;
  archived_at: string | null;
  observed_device_ids: string[];
  last_attempt_at: string | null;
  last_success_at: string | null;
  consecutive_failures: number;
  last_error: string;
}

export interface TargetCreate {
  connection_id: string;
  host: string;
  port?: number | null;
  enabled?: boolean;
  profile_id?: string | null;
  endpoint_config?: Record<string, unknown>;
  onboarding_site_id?: string | null;
}

export interface TargetPatch {
  enabled?: boolean | null;
  profile_id?: string | null;
  clear_profile?: boolean;
  onboarding_site_id?: string | null;
  clear_onboarding_site?: boolean;
  clear_host_key?: boolean;
  expected_revision: number;
}

export interface EffectiveCollection {
  source_key: string;
  target_key: string;
  target_id: string | null;
  collector_type: string;
  profile_id: string | null;
  profile_revision: number | null;
  credential_id: string | null;
  credential_revision: number | null;
  values: Record<string, unknown>;
  origins: Record<string, string>;
  frozen_normalization: Record<string, unknown>;
  resolver_version: number;
  configuration_digest: string;
}

export type ProbeRequest = Record<string, never>;

export interface ProbeResult {
  ok: boolean;
  message: string;
  effective: EffectiveCollection;
  host_key_pinned: boolean;
  duration_ms: number;
}

export interface TargetReplaceRequest {
  token: string;
  idempotency_key: string;
}

export interface TargetReplaceResponse {
  old_target: TargetView;
  new_target: TargetView;
}

export interface ProfileUsage {
  targets: number;
  connections: number;
}

export interface ProfileView {
  id: string;
  display_name: string;
  collector_type: string;
  current_revision: number;
  archived_at: string | null;
  credential_id: string | null;
  credential_revision: number | null;
  settings: Record<string, unknown>;
  usage: ProfileUsage;
  created_at: string;
  updated_at: string;
}

export interface ProfileVersionView {
  profile_id: string;
  revision: number;
  settings: Record<string, unknown>;
  credential_id: string | null;
  credential_revision: number | null;
  created_at: string;
  actor_id: string | null;
}

export interface ProfileCreate {
  display_name: string;
  collector_type: string;
  settings?: Record<string, unknown>;
  credential_id?: string | null;
}

export interface ProfilePatch {
  display_name?: string | null;
  settings?: Record<string, unknown> | null;
  credential_id?: string | null;
  clear_credential?: boolean;
  expected_revision: number;
}

export interface ImpactTarget {
  target_id: string;
  connection_id: string;
  host: string;
  device_ids: string[];
}

export interface ProfileImpact {
  profile_id: string;
  revision: number;
  targets: ImpactTarget[];
  connection_ids: string[];
  device_ids: string[];
  total_targets: number;
  total_devices: number;
  generation: Generation;
}

export interface CredentialView {
  id: string;
  display_name: string;
  current_revision: number;
  secret_paths: string[];
  archived_at: string | null;
  profiles_using: number;
  created_at: string;
  updated_at: string;
}

export interface CredentialCreate {
  display_name: string;
  secrets: Record<string, string>;
}

export interface CredentialPatch {
  display_name?: string | null;
  secrets?: Record<string, string> | null;
  expected_revision: number;
}

export interface SiteView {
  id: string;
  code: string;
  name: string;
  location: string;
  /** The site's point on the site map; both or neither. */
  lat?: number | null;
  lon?: number | null;
  /** The site group path from the top, its names joined by " / ". */
  site_group?: string | null;
  blocks?: SiteBlock[] | null;
  revision: number;
  device_count: number;
  location_count: number;
}

export interface SiteCreate {
  code: string;
  name?: string;
  location?: string;
  lat?: number | null;
  lon?: number | null;
}

export interface SitePatch {
  name?: string | null;
  location?: string | null;
  /** Both null clears the point; both absent keeps it. */
  lat?: number | null;
  lon?: number | null;
  /** Absent keeps the stored value; null or empty clears it. */
  site_group?: string | null;
  blocks?: SiteBlock[] | null;
  expected_revision: number;
}

export interface LocationView {
  id: string;
  connection_id: string;
  source_key: string;
  location_id: string;
  name: string;
  site_id: string | null;
  site_code: string | null;
  revision: number;
  device_count: number;
}

export interface LocationPatch {
  site_id: string | null;
  expected_revision: number;
}

export interface SiteSearchQuery {
  q?: string | null;
  sort?: SiteSort;
  direction?: SortDirection;
  offset?: number;
  limit?: number;
}

export interface SitePage {
  items: SiteView[];
  total: number;
  offset: number;
  limit: number;
}

export interface SiteImportRow {
  code: string;
  name?: string | null;
  location?: string | null;
}

export interface SiteImport {
  sites: SiteImportRow[];
  dry_run?: boolean;
}

export interface SiteImportRowResult {
  index: number;
  code: string;
  action: string;
  status: BulkRowStatus;
  error: string | null;
}

export interface SiteImportResult {
  applied: boolean;
  created: number;
  updated: number;
  unchanged: number;
  errors: number;
  rows: SiteImportRowResult[];
}

export interface LocationSearchQuery {
  q?: string | null;
  connection_id?: string | null;
  site_id?: string | null;
  state?: LocationState;
  offset?: number;
  limit?: number;
}

export interface LocationConnectionCount {
  connection_id: string;
  source_key: string;
  count: number;
}

export interface LocationStateCounts {
  all: number;
  mapped: number;
  unmapped: number;
  suggested: number;
}

export interface LocationMatch {
  site_id: string;
  site_code: string;
  rule: string;
}

export interface LocationRow {
  location: LocationView;
  suggestion: LocationMatch | null;
}

export interface LocationPage {
  items: LocationRow[];
  total: number;
  offset: number;
  limit: number;
  counts: LocationStateCounts;
  connections: LocationConnectionCount[];
}

export interface LocationBinding {
  id?: string | null;
  source_key?: string | null;
  location_id?: string | null;
  site_id?: string | null;
  site_code?: string | null;
  expected_revision?: number | null;
}

export interface LocationBindings {
  bindings: LocationBinding[];
  dry_run?: boolean;
}

export interface LocationBindingRowResult {
  index: number;
  id: string | null;
  source_key: string;
  location_id: string;
  name: string;
  site_before: string | null;
  site_after: string | null;
  status: BulkRowStatus;
  error: string | null;
}

export interface LocationBindingResult {
  applied: boolean;
  changed: number;
  unchanged: number;
  errors: number;
  devices_recomputed: number;
  rows: LocationBindingRowResult[];
}

export interface ViewFilter {
  version?: number;
  q?: string | null;
  site_id?: string[];
  connection_id?: string[];
  platform?: string[];
  collection_state?: CollectionState[];
  placement_state?: PlacementState[];
  lifecycle?: Lifecycle[];
}

export interface SavedViewView {
  id: string;
  owner_id: string;
  name: string;
  filter: ViewFilter;
  sort: SortField;
  direction: SortDirection;
  columns: string[];
  revision: number;
  created_at: string;
  updated_at: string;
}

export interface SavedViewCreate {
  name: string;
  filter?: ViewFilter;
  sort?: SortField;
  direction?: SortDirection;
  columns?: string[];
}

export interface SavedViewPatch {
  name?: string | null;
  filter?: ViewFilter | null;
  sort?: SortField | null;
  direction?: SortDirection | null;
  columns?: string[] | null;
  expected_revision: number;
}

export interface RoutingMemberView {
  context_uid: string;
  owner_uid: string;
  added_at: string;
  actor_id: string | null;
  present: boolean;
}

/** A routing group is an operator label on observed routing contexts. The routes and
 * route targets in the published snapshot decide how traffic can flow between contexts.
 * Group membership does not change that. */
export interface RoutingGroupView {
  id: string;
  display_name: string;
  description: string;
  revision: number;
  archived_at: string | null;
  members: RoutingMemberView[];
  created_at: string;
  updated_at: string;
}

export interface RoutingGroupCreate {
  display_name: string;
  description?: string;
  context_uids?: string[];
}

export interface RoutingGroupPatch {
  display_name?: string | null;
  description?: string | null;
  expected_revision: number;
}

export interface Selection {
  ids?: string[] | null;
  filter?: DeviceListQuery | null;
  snapshot_key?: string | null;
  intent_generation?: number | null;
}

export interface PlacementChange {
  mode: PlacementMode;
  site_id?: string | null;
}

export interface ProfileAssignmentChange {
  profile_id: string | null;
}

export interface RoutingMembersChange {
  group_id: string;
  add_context_uids?: string[];
  remove_context_uids?: string[];
}

export interface ReplacementChange {
  endpoint_config: Record<string, unknown>;
  secrets?: Record<string, string>;
}

export interface PreviewRequest {
  operation: PreviewOperation;
  selection: Selection;
  change?: Record<string, unknown> | null;
}

export interface PreviewMember {
  kind: PreviewMemberKind;
  id: string;
  revision: number;
  label: string;
}

export interface PreviewResponse {
  token: string;
  operation: PreviewOperation;
  expires_at: string;
  generation: Generation;
  members: PreviewMember[];
  member_count: number;
  affected_device_count: number;
  affected_target_count: number;
  changes: Record<string, unknown>;
  warnings: string[];
}

export interface ApplyRequest {
  token: string;
  idempotency_key: string;
}

export interface ApplyResult {
  kind: PreviewMemberKind;
  id: string;
  revision: number;
}

export interface ApplyResponse {
  token: string;
  operation: PreviewOperation;
  status: ApplyStatus;
  generation: Generation;
  results: ApplyResult[];
  job_ids: number[];
}

export interface ImpactItem {
  kind: PreviewMemberKind;
  entity_id: string;
  detail: Record<string, unknown>;
}

export interface ImpactPage {
  items: ImpactItem[];
  next_cursor: string | null;
  total: number;
  generation: Generation;
}

export interface FieldMetadata {
  path: string;
  variant: string | null;
  category: FieldCategory;
  secret: boolean;
  identity_sensitivity: IdentitySensitivity;
  profile_applicability: string;
  label: string;
  /** The endpoint role from src/hst/app/inventory/field_metadata.py ENDPOINT_ROLES. */
  endpoint?: "" | "destination" | "verify" | "trust" | "pin";
}

export interface CollectorFieldMetadata {
  collector_type: string;
  kind: ConnectionKind;
  fields: FieldMetadata[];
}

export interface InventoryStateView {
  resolver_version: number;
  schema_version: number;
  backfill_version: number;
  activation_state: ActivationState;
  read_model_snapshot_key: string | null;
  intent_generation: number;
  inventory_sync_pending: boolean;
  updated_at: string;
}

// --- error helpers ------------------------------------------------------------------

/** The body a refused inventory call carries; ApiError preserves its recovery fields. */
export type InventoryErrorBody = ErrorResponse;

/** Status the backend uses for each error code (ERROR_STATUS in contracts.py). */
export const ERROR_STATUS: Readonly<Record<ErrorCode, number>> = {
  inventory_changed: 409,
  normalization_migrated: 409,
  stale_revision: 409,
  preview_expired: 409,
  forbidden: 403,
  not_found: 404,
  validation: 422,
  observed_store_unavailable: 503,
  conflict: 409,
  idempotency_conflict: 409,
};

/** The permission an apply of each operation rechecks (OPERATION_PERMISSIONS). */
export const OPERATION_PERMISSIONS: Readonly<Record<PreviewOperation, string>> = {
  place_devices: "sites.write",
  assign_target_profile: "sources.write",
  edit_profile: "sources.write",
  rotate_credential: "sources.write",
  delete_site: "sites.write",
  delete_connection: "sources.write",
  delete_target: "sources.write",
  replace_target: "sources.write",
  edit_routing_members: "sources.write",
  archive_devices: INVENTORY_WRITE,
  restore_devices: INVENTORY_WRITE,
};

// --- query string helpers ----------------------------------------------------------------

function query(params: object): string {
  const q = new URLSearchParams();
  for (const [key, value] of Object.entries(params as Record<string, unknown>)) {
    if (value === undefined || value === null) continue;
    if (Array.isArray(value)) {
      for (const v of value) q.append(key, String(v));
    } else {
      q.set(key, String(value));
    }
  }
  const text = q.toString();
  return text ? `?${text}` : "";
}

const p = (path: string) => `${API_PREFIX}${path}`;
const seg = (id: string) => encodeURIComponent(id);

// --- client: one function per C07 route -----------------------------------------------------

export const inventoryApi = {
  // devices
  listDevices: (params: DeviceListQuery = {}) => api<DevicePage>(p(`/devices${query(params)}`)),
  getDevice: (id: string) => api<DeviceDetail>(p(`/devices/${seg(id)}`)),
  getDeviceRouting: (id: string, params: DeviceRoutingQuery = {}) =>
    api<DeviceRoutingResponse>(p(`/devices/${seg(id)}/routing${query(params)}`)),
  getDeviceHistory: (id: string, params: PageQuery = {}) =>
    api<EventPage>(p(`/devices/${seg(id)}/history${query(params)}`)),
  patchPlacement: (id: string, body: PlacementPatch) =>
    api<DeviceDetail>(p(`/devices/${seg(id)}/placement`), { method: "PATCH", body }),
  patchLifecycle: (id: string, body: LifecyclePatch) =>
    api<DeviceSummary>(p(`/devices/${seg(id)}/lifecycle`), { method: "PATCH", body }),
  collectDevice: (id: string, body: CollectRequest) =>
    api<CollectResponse>(p(`/devices/${seg(id)}/collect`), { method: "POST", body }),

  // connections
  listConnections: (params: ConnectionListQuery = {}) => api<ConnectionView[]>(p(`/connections${query(params)}`)),
  getConnection: (id: string) => api<ConnectionView>(p(`/connections/${seg(id)}`)),
  createConnection: (body: ConnectionCreate) => api<ConnectionView>(p("/connections"), { method: "POST", body }),
  patchConnection: (id: string, body: ConnectionPatch) =>
    api<ConnectionView>(p(`/connections/${seg(id)}`), { method: "PATCH", body }),
  deleteConnection: (id: string, body: ApplyRequest) =>
    api<ApplyResponse>(p(`/connections/${seg(id)}`), { method: "DELETE", body }),

  // targets
  listTargets: (params: { connection_id?: string } = {}) => api<TargetView[]>(p(`/targets${query(params)}`)),
  getTarget: (id: string) => api<TargetView>(p(`/targets/${seg(id)}`)),
  createTarget: (body: TargetCreate) => api<TargetView>(p("/targets"), { method: "POST", body }),
  patchTarget: (id: string, body: TargetPatch) => api<TargetView>(p(`/targets/${seg(id)}`), { method: "PATCH", body }),
  deleteTarget: (id: string, body: ApplyRequest) =>
    api<ApplyResponse>(p(`/targets/${seg(id)}`), { method: "DELETE", body }),
  getEffective: (id: string) => api<EffectiveCollection>(p(`/targets/${seg(id)}/effective`)),
  probeTarget: (id: string, body: ProbeRequest = {}) =>
    api<ProbeResult>(p(`/targets/${seg(id)}/probe`), { method: "POST", body }),
  replaceTarget: (id: string, body: TargetReplaceRequest) =>
    api<TargetReplaceResponse>(p(`/targets/${seg(id)}/replace`), { method: "POST", body }),

  // profiles and credentials
  listProfiles: (params: { collector_type?: string } = {}) => api<ProfileView[]>(p(`/profiles${query(params)}`)),
  getProfile: (id: string) => api<ProfileView>(p(`/profiles/${seg(id)}`)),
  createProfile: (body: ProfileCreate) => api<ProfileView>(p("/profiles"), { method: "POST", body }),
  patchProfile: (id: string, body: ProfilePatch) => api<ProfileView>(p(`/profiles/${seg(id)}`), { method: "PATCH", body }),
  deleteProfile: (id: string, expectedRevision: number) =>
    api<void>(p(`/profiles/${seg(id)}${query({ expected_revision: expectedRevision })}`), { method: "DELETE" }),
  getProfileImpact: (id: string) => api<ProfileImpact>(p(`/profiles/${seg(id)}/impact`)),
  listCredentials: () => api<CredentialView[]>(p("/credentials")),
  getCredential: (id: string) => api<CredentialView>(p(`/credentials/${seg(id)}`)),
  createCredential: (body: CredentialCreate) => api<CredentialView>(p("/credentials"), { method: "POST", body }),
  patchCredential: (id: string, body: CredentialPatch) =>
    api<CredentialView>(p(`/credentials/${seg(id)}`), { method: "PATCH", body }),
  deleteCredential: (id: string, expectedRevision: number) =>
    api<void>(p(`/credentials/${seg(id)}${query({ expected_revision: expectedRevision })}`), { method: "DELETE" }),

  // sites and locations
  listSites: () => api<SiteView[]>(p("/sites")),
  searchSites: (params: SiteSearchQuery = {}) => api<SitePage>(p(`/sites/search${query(params)}`)),
  getSite: (id: string) => api<SiteView>(p(`/sites/${seg(id)}`)),
  createSite: (body: SiteCreate) => api<SiteView>(p("/sites"), { method: "POST", body }),
  importSites: (body: SiteImport) => api<SiteImportResult>(p("/sites/import"), { method: "POST", body }),
  patchSite: (id: string, body: SitePatch) => api<SiteView>(p(`/sites/${seg(id)}`), { method: "PATCH", body }),
  deleteSite: (id: string, body: ApplyRequest) => api<ApplyResponse>(p(`/sites/${seg(id)}`), { method: "DELETE", body }),
  listLocations: (params: { connection_id?: string } = {}) => api<LocationView[]>(p(`/locations${query(params)}`)),
  searchLocations: (params: LocationSearchQuery = {}) => api<LocationPage>(p(`/locations/search${query(params)}`)),
  bindLocations: (body: LocationBindings) =>
    api<LocationBindingResult>(p("/locations/bindings"), { method: "POST", body }),
  patchLocation: (id: string, body: LocationPatch) =>
    api<LocationView>(p(`/locations/${seg(id)}`), { method: "PATCH", body }),

  // saved views
  listViews: () => api<SavedViewView[]>(p("/views")),
  getView: (id: string) => api<SavedViewView>(p(`/views/${seg(id)}`)),
  createView: (body: SavedViewCreate) => api<SavedViewView>(p("/views"), { method: "POST", body }),
  patchView: (id: string, body: SavedViewPatch) => api<SavedViewView>(p(`/views/${seg(id)}`), { method: "PATCH", body }),
  deleteView: (id: string, expectedRevision: number) =>
    api<void>(p(`/views/${seg(id)}${query({ expected_revision: expectedRevision })}`), { method: "DELETE" }),

  // routing groups
  listRoutingGroups: () => api<RoutingGroupView[]>(p("/routing-groups")),
  getRoutingGroup: (id: string) => api<RoutingGroupView>(p(`/routing-groups/${seg(id)}`)),
  createRoutingGroup: (body: RoutingGroupCreate) =>
    api<RoutingGroupView>(p("/routing-groups"), { method: "POST", body }),
  patchRoutingGroup: (id: string, body: RoutingGroupPatch) =>
    api<RoutingGroupView>(p(`/routing-groups/${seg(id)}`), { method: "PATCH", body }),
  // PreviewOperation has no delete_routing_group (C07).
  deleteRoutingGroup: (id: string, expectedRevision: number) =>
    api<void>(p(`/routing-groups/${seg(id)}${query({ expected_revision: expectedRevision })}`), { method: "DELETE" }),

  // operations
  preview: (body: PreviewRequest) => api<PreviewResponse>(p("/operations/preview"), { method: "POST", body }),
  apply: (body: ApplyRequest) => api<ApplyResponse>(p("/operations/apply"), { method: "POST", body }),
  previewImpact: (token: string, params: PageQuery = {}) =>
    api<ImpactPage>(p(`/operations/previews/${seg(token)}/impact${query(params)}`)),

  // metadata and state
  fieldMetadata: () => api<CollectorFieldMetadata[]>(p("/field-metadata")),
  state: () => api<InventoryStateView>(p("/state")),
};

export type InventoryApi = typeof inventoryApi;
