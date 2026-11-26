import type { ResultValue } from "../results/text";
import type { Requirement } from "../assessments/types";
import type { SnapshotReference } from "../analysis/contracts";
import type { MtuRequest } from "../api/types";

export type InventoryKind = "device" | "interface" | "ip" | "network" | "dns" | "service_requirement" | "vrf" | "identity" | "segment";

export interface InventoryReference {
  kind: InventoryKind;
  uid: string;
  role: "source" | "destination" | "component" | "shared";
  context?: string | null;
}

/** A described object that is not bound to inventory yet (schema version 2). */
export interface Placeholder {
  text: string;
  expected_kind?: InventoryKind | null;
  status: "unresolved" | "ambiguous";
  candidates: string[];
  note?: string | null;
}

/** A member states exactly one of `address`, `inventory` or `placeholder`. */
export interface ApplicationMember {
  id: string;
  name?: string | null;
  address?: string | null;
  inventory?: InventoryReference | null;
  context?: string | null;
  placeholder?: Placeholder | null;
}

export interface ComponentGroup {
  id: string;
  name: string;
  description?: string | null;
  members: ApplicationMember[];
}

export interface ApplicationService {
  id: string;
  name: string;
  description?: string | null;
  connection_ids: string[];
  component_roles: Array<{ group_id: string; role: "client" | "endpoint" | "dependency" | "component" }>;
}

export interface DestinationCondition {
  kind: "member" | "and" | "or" | "threshold";
  member?: string | null;
  n?: number | null;
  parts: DestinationCondition[];
}

export interface EndpointContext {
  vrf?: string | null;
  device_uid?: string | null;
  identity_uid?: string | null;
  segment_uid?: string | null;
  ingress_interface_uid?: string | null;
}

export interface ApplicationConnection {
  id: string;
  name: string;
  description?: string | null;
  source: string;
  destination: string;
  protocol?: string | null;
  destination_ports?: Array<number | string> | null;
  source_ports?: Array<number | string> | null;
  success: "forward" | "round-trip" | "session";
  destination_condition: DestinationCondition;
  source_context?: EndpointContext | null;
  destination_context?: EndpointContext | null;
  header_constraints?: Record<string, Array<[number, number]>>;
  mtu?: MtuRequest | null;
  provenance?: Record<string, unknown> | null;
}

/** A placeholder member requires schema version 2 and keeps `state` at draft. */
export interface BusinessApplicationDefinition {
  schema_version: 1 | 2;
  kind: "BusinessApplication";
  id: string;
  name: string;
  description?: string | null;
  owner?: string | null;
  environment?: string | null;
  state: "draft" | "ready";
  services: ApplicationService[];
  groups: ComponentGroup[];
  connections: ApplicationConnection[];
}

/** Where a revision came from. `validation` summarizes the stored validation
 *  the author saved with, and is null when the revision was saved without one. */
export interface RevisionOrigin {
  source: "import" | "editor" | "api" | "trace" | "generator";
  generation_id: string | null;
  generated_digest: string | null;
  validation: { validation_digest: string; snapshot: { snapshot: string; manifest_sha256: string; estate: string }; definition_digest: string; ready: boolean; blocking_count: number } | null;
}

export interface ApplicationRevision {
  id: string;
  revision: number;
  name: string;
  definition: BusinessApplicationDefinition;
  digest: string;
  created_by: number | null;
  created_at: string;
  /** Absent or null on a revision without a recorded origin. */
  origin?: RevisionOrigin | null;
}

export interface ResolutionIssue { code: string; path: string; detail: string; severity: string }
export interface ResolvedApplication {
  application: { id: string; revision: number; digest: string };
  snapshot: SnapshotReference;
  digest: string;
  ready: boolean;
  selection: { service_ids: string[]; connection_ids: string[] };
  groups: Record<string, Record<string, { bindings: Array<{ address: string; context?: string | null; object_uid?: string | null }>; inventory_uid?: string | null; evidence: string[] }>>;
  connections: Array<{
    id: string;
    service_id?: string | null;
    readiness: "ready" | "unresolved";
    request?: Requirement | null;
    issues: ResolutionIssue[];
  }>;
  issues: ResolutionIssue[];
}

export interface ImportPreview {
  application_id: string;
  base_revision: number;
  base_digest: string;
  result_digest: string;
  preview_digest: string;
  definition: BusinessApplicationDefinition;
  changes: Record<string, string[]>;
  mapping_issues: Array<{ code: string; path: string; detail: string }>;
  no_op: boolean;
}

/** A parse or schema error. `line` and `column` count from 1 and are null for
 *  an error that has no place in the text. */
export interface ValidationIssue { path: string; message: string; line: number | null; column: number | null }
export interface ValidationWarning { code: string; path: string; message: string }

/** The stage 4 record of one connection. `result` and the source prefixes
 *  come from the evaluation's `outcomes.after`; a connection that was not
 *  evaluated has a null result and a reason. */
export interface FlowCheck {
  connection_id: string;
  readiness: "ready" | "unresolved";
  /** the answer to the statement that the connection condition holds; null when not evaluated */
  result: ResultValue | null;
  passes: string[];
  fails: string[];
  open: string[];
  missing_evidence: string[];
  not_evaluated_reason: "not-ready" | "over-cap" | "deadline" | "capacity-busy" | "evaluation-failed" | null;
  detail: string | null;
}

/** POST /business-applications/validate. The resolution is never saved:
 *  `resolution` is the document at the snapshot, and `blocking` lists every
 *  path that blocks the ready state. `flows` is null unless the request set
 *  `evaluate`; a flow check result never blocks the ready state. */
export interface ValidationResult {
  errors: ValidationIssue[];
  warnings: ValidationWarning[];
  definition: BusinessApplicationDefinition | null;
  preview: ImportPreview | null;
  resolution: ResolvedApplication | null;
  flows: FlowCheck[] | null;
  blocking: string[];
  snapshot: SnapshotReference;
  /** The stored validation record, only when the request asked to record it. */
  validation_digest?: string | null;
}

/** One group member of a generated definition as the post-processor decided
 *  it. A placeholder row has no `kind` or `uid`; its `alternatives` are the
 *  placeholder's candidates. `evidence` names the steps, numbered from 1, whose
 *  results name the reference. */
export interface GenerationReference {
  path: string;
  phrase: string;
  status: "resolved" | "ambiguous" | "unresolved";
  selection: "exact" | "model-choice" | "none";
  kind: InventoryKind | null;
  uid: string | null;
  bindings: Array<{ address: string; context?: string | null }>;
  alternatives: string[];
  chain: Array<{ from: string; rel: string; to: string }>;
  evidence: Array<{ step: number; tool: string; arguments: Record<string, unknown> }>;
  issues: ResolutionIssue[];
}

/** The generation report. `related` lists objects searches returned that
 *  the definition does not name and that matter to the request, each with
 *  the step that returned it (`relation`) and why it is listed (`reason`);
 *  `related_omitted` counts the other objects searches returned. `blocking`
 *  lists the members that keep the ready state unavailable. */
export interface GenerationReport {
  generation_id: string;
  snapshot: SnapshotReference;
  definition_digest: string | null;
  references: GenerationReference[];
  related: Array<{ uid: string; label?: string | null; name?: string | null; relation: string; reason: string }>;
  related_omitted?: number;
  blocking: string[];
}

/** An edit of a saved revision. Its commit states this base revision and
 *  digest, and the server answers 409 when the application changed since. */
export interface EditSource {
  kind: "edit";
  application_id: string;
  base_revision: number;
  base_digest: string;
}

/** What a generation started from: a description, messages of a chat, or a
 *  saved revision to edit. */
export type GenerationSource =
  | { kind: "description" }
  | { kind: "conversation"; conversation_id: string; message_ids: string[] }
  | EditSource;

/** GET /business-applications/generations/{id}. While the generation runs
 *  the result holds only `status`; a failed one holds `detail`. A finished
 *  one holds the YAML, which is the model's text with `errors` when it did not
 *  parse. `validation.preview` and `validation_digest` are null for a caller
 *  without changes.write. */
export interface GenerationResult {
  status: "running" | "done" | "error";
  detail?: string;
  generation_id?: string;
  created_at?: string | null;
  snapshot?: SnapshotReference | null;
  source?: GenerationSource | null;
  yaml?: string;
  errors?: ValidationIssue[];
  report?: GenerationReport | null;
  validation?: ValidationResult | null;
  validation_digest?: string | null;
}

/** The generation a draft workspace shows, kept on the workspace pane. */
export interface ApplicationDraftRef {
  generationId: string;
}

/** The saved revision an "Edit with AI" draft starts from. */
export interface ApplicationEditTarget {
  applicationId: string;
  revision: number;
  name: string;
}
