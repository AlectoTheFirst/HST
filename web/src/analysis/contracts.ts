import type { ResultValue } from "../results/text";
import type { Requirement } from "../assessments/types";

export type AnalysisSection = "results" | "scope" | "history" | "verification";

export interface SnapshotReference {
  snapshot: string;
  manifest_sha256: string;
  estate: string;
  observation_floor_ms?: number | null;
}

export interface RevisionReference { id: string; revision: number; digest?: string | null }
export interface ApplicationConnectionReference {
  application: RevisionReference;
  service_id: string;
  connection_id: string;
}

export type ConnectionSource =
  | { kind: "inline"; request: Requirement }
  | { kind: "saved_requirement"; requirement: RevisionReference; request: Requirement }
  | { kind: "graph_requirement"; requirement_uid: string }
  | { kind: "application_connection"; reference: ApplicationConnectionReference; request: Requirement; resolved_scope_digest: string };

export interface ConnectionSelection { id: string; name: string; source: ConnectionSource }
export interface ChangeIntent { kind: string; params: Record<string, unknown> }

export interface ConnectionAnalysisInput {
  kind: "connection";
  snapshot: SnapshotReference;
  connections: ConnectionSelection[];
  changes: ChangeIntent[];
  mode: "possible" | "guaranteed";
}

export interface SimulationFlow { src: string; dst: string; port?: number | null; proto?: string | null }
export interface SimulationScope { flows: SimulationFlow[]; sites: string[] }
export interface SimulationBounds { depth?: number | null; max_flows: number; max_seconds: number }
export type Protection =
  | { kind: "inline"; name: string; request: Requirement; desired: "holds" | "isolated" }
  | { kind: "application_connection"; reference: ApplicationConnectionReference; resolved_scope_digest: string; desired: "holds" | "isolated" };

export interface SimulationAnalysisInput {
  kind: "simulation";
  snapshot: SnapshotReference;
  changes: ChangeIntent[];
  change_revision?: RevisionReference | null;
  scope?: SimulationScope | null;
  bounds: SimulationBounds;
  protected: Protection[];
}

export type AnalysisInput = ConnectionAnalysisInput | SimulationAnalysisInput;
export type ExecutionState = "queued" | "running" | "completed" | "failed" | "cancelled";
export type CoverageState = "not_started" | "partial" | "complete";

export interface AnalysisRunSummary {
  id: string;
  item_id: string;
  execution: ExecutionState;
  /** the run's answer (passes, fails, not decided); null when the run has none */
  result?: ResultValue | null;
  coverage: CoverageState;
  result_ref?: string | null;
}

export interface AnalysisSession {
  schema_version: 1;
  id: string;
  revision: number;
  title: string;
  input: AnalysisInput;
  runs: AnalysisRunSummary[];
  legacy_assessment?: { assessment_id: string; assessment_revision: number } | null;
}

export interface AnalysisSessionRecord {
  id: string;
  revision: number;
  title: string;
  definition: AnalysisSession;
  results: Record<string, unknown>;
  input_digest: string;
  created_by: number | null;
  created_at: string;
}

