import { useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, apiDownload, ApiError } from "../api/client";
import { atLeast, useAuth } from "../auth";
import { PinnedSnapshotPicker } from "../assessments/PinnedSnapshotPicker";
import { AnalysisResult } from "../assessments/AnalysisResult";
import type { AnalysisRun, SavedRequirement } from "../assessments/types";
import { IntentEditor } from "../assessments/IntentEditor";
import type { Intent } from "../assessments/types";
import AssessmentsPage from "../assessments/AssessmentsPage";
import ChangeSimPage from "../changesim/ChangeSimPage";
import type { ApplicationRevision, ResolvedApplication } from "../applications/types";
import type {
  AnalysisRunSummary,
  AnalysisSection,
  AnalysisSessionRecord,
  Protection,
  SimulationAnalysisInput,
  SnapshotReference,
} from "./contracts";
import { useAiContext, useAiPaneId } from "../ai/context";
import { useAiDrawer, useOpenConversation } from "../ai/drawer";
import { SessionRunComparison } from "./SessionRunComparison";
import "./analysis.css";
import "../changesim/changesim.css";

/** Whether the viewer can read conversation `id`. The server answers 404 for
 *  a conversation of another user. */
async function readable(id: string): Promise<boolean> {
  try {
    await api(`/ai/conversations/${encodeURIComponent(id)}`);
    return true;
  } catch (cause) {
    if (cause instanceof ApiError && cause.status === 404) return false;
    throw cause;
  }
}

function download(value: Awaited<ReturnType<typeof apiDownload>>) {
  const url = URL.createObjectURL(value.blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = value.filename;
  link.click();
  URL.revokeObjectURL(url);
}

function RunResult({ id }: { id: string }) {
  const run = useQuery({
    queryKey: ["analysis-run", id],
    queryFn: () => api<AnalysisRun>(`/analysis-jobs/${encodeURIComponent(id)}`),
    refetchInterval: (query) =>
      ["queued", "running"].includes(query.state.data?.state ?? "") ? 1000 : false,
  });
  if (run.isLoading) return <p role="status">Loading run</p>;
  if (run.isError) return <p role="alert">Run not loaded</p>;
  return (
    <article className="analysis-run-card">
      <div className="analysis-status">
        <strong>{run.data!.kind}</strong>
        <span>Execution: {run.data!.state}</span>
      </div>
      {run.data!.progress && <p>Progress: {JSON.stringify(run.data!.progress)}</p>}
      {run.data!.error != null && <p role="alert">{String(run.data!.error)}</p>}
      {run.data!.result && <AnalysisResult result={run.data!.result} />}
    </article>
  );
}

/** Session execution and coverage, derived from the child runs. */
export function sessionState(
  runs: AnalysisRunSummary[],
  omitted: number,
): { execution: string; coverage: string } {
  if (runs.length === 0) return { execution: "not started", coverage: "not started" };
  const states = runs.map((run) => run.execution);
  const execution = states.some((state) => state === "queued" || state === "running")
    ? "running"
    : states.includes("failed")
      ? "failed"
      : states.includes("cancelled")
        ? "cancelled"
        : "completed";
  const complete =
    omitted === 0 &&
    runs.every((run) => run.execution === "completed" && run.coverage === "complete");
  return { execution, coverage: complete ? "complete" : "partial" };
}

function simulationFlows(result?: Record<string, unknown>): Record<string, unknown>[] {
  return Array.isArray(result?.flows)
    ? result.flows.filter(
        (item): item is Record<string, unknown> => !!item && typeof item === "object",
      )
    : [];
}

/** Whether a saved simulation result holds a prediction: Results shows it as
 *  Predicted, and only then does Verification have one to compare. */
function hasPrediction(result?: Record<string, unknown>): boolean {
  return (
    simulationFlows(result).some((item) => item.after != null) ||
    (!!result &&
      ["predicted", "routing_consequence", "changed_devices"].some((key) => result[key] != null))
  );
}

function SimulationComparison({
  result,
  snapshot,
}: {
  result?: Record<string, unknown>;
  snapshot: string;
}) {
  const flows = simulationFlows(result);
  return (
    <div className="chgsim-compare">
      <section className="chgsim-pane">
        <h3>Baseline</h3>
        <p>Pinned snapshot {snapshot}</p>
        {flows.length > 0 ? (
          flows.map((flow, index) => (
            <article key={index}>
              <strong>{JSON.stringify(flow.flow ?? `Flow ${index + 1}`)}</strong>
              <pre>{JSON.stringify(flow.before ?? null, null, 2)}</pre>
            </article>
          ))
        ) : (
          <p>No traffic flow evaluated</p>
        )}
      </section>
      <section className="chgsim-pane">
        <h3>Predicted</h3>
        {hasPrediction(result) ? (
          flows.length > 0 ? (
            flows.map((flow, index) => (
              <article key={index}>
                <strong>{JSON.stringify(flow.flow ?? `Flow ${index + 1}`)}</strong>
                <pre>{JSON.stringify(flow.after ?? null, null, 2)}</pre>
              </article>
            ))
          ) : (
            <pre>{JSON.stringify(result?.predicted ?? result, null, 2)}</pre>
          )
        ) : (
          <p>No prediction</p>
        )}
      </section>
    </div>
  );
}

function SimulationBuilder({ onCreated }: { onCreated: (id: string) => void }) {
  const [title, setTitle] = useState("Change analysis");
  const [snapshot, setSnapshot] = useState("");
  const [intents, setIntents] = useState<Intent[]>([]);
  const [flows, setFlows] = useState<
    Array<{ src: string; dst: string; proto?: string; port?: number }>
  >([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [applicationId, setApplicationId] = useState("");
  const [connectionId, setConnectionId] = useState("");
  const [protectedItems, setProtectedItems] = useState<
    Array<{ label: string; protection: Protection }>
  >([]);
  const applications = useQuery({
    queryKey: ["business-applications"],
    queryFn: () => api<{ applications: ApplicationRevision[] }>("/business-applications"),
  });
  const requirements = useQuery({
    queryKey: ["requirements"],
    queryFn: () => api<{ requirements: SavedRequirement[] }>("/requirements"),
  });
  const application = applications.data?.applications.find((item) => item.id === applicationId);
  const associated =
    application?.definition.connections.filter((connection) =>
      application.definition.services.some((service) =>
        service.connection_ids.includes(connection.id),
      ),
    ) ?? [];

  async function addApplicationProtection() {
    if (!application || !connectionId || !snapshot) return;
    setBusy(true);
    setError("");
    try {
      const resolved = await api<ResolvedApplication>(
        `/business-applications/${encodeURIComponent(application.id)}/resolve`,
        { method: "POST", body: { snapshot, connection_ids: [connectionId] } },
      );
      const connection = resolved.connections.find((item) => item.id === connectionId);
      if (!connection || connection.readiness !== "ready" || !connection.service_id)
        throw new Error("Connection not resolved or not associated with a service");
      if (
        protectedItems.some(
          (item) =>
            item.protection.kind === "application_connection" &&
            item.protection.reference.application.id === application.id &&
            item.protection.reference.connection_id === connectionId,
        )
      )
        return;
      setProtectedItems([
        ...protectedItems,
        {
          label: `${application.name}: ${connectionId}`,
          protection: {
            kind: "application_connection",
            reference: {
              application: {
                id: application.id,
                revision: application.revision,
                digest: application.digest,
              },
              service_id: connection.service_id,
              connection_id: connectionId,
            },
            resolved_scope_digest: resolved.digest,
            desired: "holds",
          },
        },
      ]);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Protection not reviewed");
    } finally {
      setBusy(false);
    }
  }

  function addRequirement(requirement: SavedRequirement) {
    if (
      !requirement.definition.request ||
      protectedItems.some(
        (item) => item.protection.kind === "inline" && item.protection.name === requirement.title,
      )
    )
      return;
    setProtectedItems([
      ...protectedItems,
      {
        label: requirement.title,
        protection: {
          kind: "inline",
          name: requirement.title,
          request: requirement.definition.request,
          desired: "holds",
        },
      },
    ]);
  }
  async function create(run: boolean) {
    setBusy(true);
    setError("");
    try {
      const reference = await api<SnapshotReference>(
        `/analysis-snapshot?snapshot=${encodeURIComponent(snapshot)}`,
      );
      const input: SimulationAnalysisInput = {
        kind: "simulation",
        snapshot: reference,
        changes: intents,
        scope: { flows, sites: [] },
        bounds: { max_flows: 50, max_seconds: 30 },
        protected: protectedItems.map((item) => item.protection),
      };
      const record = await api<AnalysisSessionRecord>("/analysis-sessions", {
        method: "POST",
        body: { title, input },
      });
      if (run)
        await api(`/analysis-sessions/${encodeURIComponent(record.id)}/runs`, {
          method: "POST",
          body: { session_revision: record.revision, input_digest: record.input_digest },
        });
      onCreated(record.id);
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : run ? "Simulation not run" : "Draft not saved",
      );
    } finally {
      setBusy(false);
    }
  }
  const incomplete =
    busy ||
    !snapshot ||
    !title.trim() ||
    intents.length === 0 ||
    protectedItems.length > 50 ||
    flows.some((flow) => !flow.src || !flow.dst);
  return (
    <section aria-label="Change simulation">
      <h3>Change simulation</h3>
      <div className="application-fields">
        <label>
          Analysis title
          <input value={title} onChange={(event) => setTitle(event.target.value)} />
        </label>
        <PinnedSnapshotPicker label="Pinned snapshot" value={snapshot} onChange={setSnapshot} />
      </div>
      <IntentEditor value={intents} onChange={setIntents} />
      <h4>Traffic scope</h4>
      {flows.map((flow, index) => (
        <div className="analysis-flow" key={index}>
          <label>
            Source
            <input
              value={flow.src}
              onChange={(event) =>
                setFlows(
                  flows.map((item, i) =>
                    i === index ? { ...item, src: event.target.value } : item,
                  ),
                )
              }
            />
          </label>
          <label>
            Destination
            <input
              value={flow.dst}
              onChange={(event) =>
                setFlows(
                  flows.map((item, i) =>
                    i === index ? { ...item, dst: event.target.value } : item,
                  ),
                )
              }
            />
          </label>
          <label>
            Protocol
            <input
              value={flow.proto ?? ""}
              onChange={(event) =>
                setFlows(
                  flows.map((item, i) =>
                    i === index ? { ...item, proto: event.target.value || undefined } : item,
                  ),
                )
              }
            />
          </label>
          <label>
            Port
            <input
              type="number"
              min={0}
              max={65535}
              value={flow.port ?? ""}
              onChange={(event) =>
                setFlows(
                  flows.map((item, i) =>
                    i === index
                      ? {
                          ...item,
                          port: event.target.value ? Number(event.target.value) : undefined,
                        }
                      : item,
                  ),
                )
              }
            />
          </label>
          <button type="button" onClick={() => setFlows(flows.filter((_, i) => i !== index))}>
            Remove flow
          </button>
        </div>
      ))}
      <button type="button" onClick={() => setFlows([...flows, { src: "", dst: "" }])}>
        Add traffic flow
      </button>
      <h4>Protected requirements</h4>
      <div className="application-fields">
        <label>
          Business application
          <select
            value={applicationId}
            onChange={(event) => {
              setApplicationId(event.target.value);
              setConnectionId("");
            }}
          >
            <option value="">Choose application</option>
            {applications.data?.applications.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Connection
          <select
            value={connectionId}
            disabled={!application}
            onChange={(event) => setConnectionId(event.target.value)}
          >
            <option value="">Choose connection</option>
            {associated.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name}
              </option>
            ))}
          </select>
        </label>
      </div>
      <button
        type="button"
        disabled={busy || !snapshot || !connectionId}
        onClick={() => void addApplicationProtection()}
      >
        Add application protection
      </button>
      <details>
        <summary>Add saved requirement</summary>
        {requirements.data?.requirements.map((item) => (
          <button
            type="button"
            key={item.id}
            disabled={!item.definition.request}
            onClick={() => addRequirement(item)}
          >
            {item.title}
          </button>
        ))}
      </details>
      {protectedItems.map((item, index) => (
        <div className="application-row" key={`${item.protection.kind}:${item.label}`}>
          <strong>{item.label}</strong>
          <span>Desired: {item.protection.desired}</span>
          <button
            type="button"
            onClick={() => setProtectedItems(protectedItems.filter((_, i) => i !== index))}
          >
            Remove protection
          </button>
        </div>
      ))}
      <p role="status">{protectedItems.length} of 50 protections selected</p>
      <div className="assessment-actions">
        <button type="button" disabled={incomplete} onClick={() => void create(false)}>
          Save draft
        </button>
        <button type="button" disabled={incomplete} onClick={() => void create(true)}>
          {busy ? "Running" : "Save and run"}
        </button>
      </div>
      {error && <p role="alert">{error}</p>}
    </section>
  );
}

export default function AnalysisWorkspace({
  sessionId,
  section: shownSection,
  onSection,
  runId: shownRun,
  onRun,
  legacyAssessmentId,
  legacyRunId,
  legacySimulation,
  conversationId,
  onConversation,
  onNavigate,
  onNavigateLegacy = () => undefined,
}: {
  sessionId?: string;
  section?: AnalysisSection;
  onSection?: (section: AnalysisSection) => void;
  runId?: string;
  onRun?: (runId: string | undefined) => void;
  legacyAssessmentId?: string;
  legacyRunId?: string;
  legacySimulation?: boolean;
  conversationId?: string;
  onConversation?: (id: string | undefined) => void;
  onNavigate: (id?: string) => void;
  onNavigateLegacy?: (assessmentId?: string, runId?: string) => void;
}) {
  const { user } = useAuth();
  const canRun = !!user && atLeast(user.role, "operator");
  const queryClient = useQueryClient();
  const selected = sessionId;
  const [ownSection, setOwnSection] = useState<AnalysisSection>("results");
  // a pane that owns the section shows Results when it holds none (Back to
  // an entry before a tab was chosen, or another session opened)
  const section = onSection ? (shownSection ?? "results") : ownSection;
  const setSection = (next: AnalysisSection) => {
    setOwnSection(next);
    onSection?.(next);
  };
  // the selected child run, carried in the link as analysis_run
  const [ownRun, setOwnRun] = useState<string>();
  const selectedRun = onRun ? shownRun : ownRun;
  const selectRun = (next: string | undefined) => {
    setOwnRun(next);
    onRun?.(next);
  };
  const selectedRow = useRef<HTMLDivElement>(null);
  const [historical, setHistorical] = useState<{ sessionId: string; revision: number }>();
  const revision =
    historical && historical.sessionId === selected ? historical.revision : undefined;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const sessions = useQuery({
    queryKey: ["analysis-sessions"],
    queryFn: () => api<{ sessions: AnalysisSessionRecord[] }>("/analysis-sessions"),
  });
  const detail = useQuery({
    queryKey: ["analysis-session", selected, revision],
    queryFn: () =>
      api<AnalysisSessionRecord>(
        `/analysis-sessions/${encodeURIComponent(selected!)}${revision ? `?revision=${revision}` : ""}`,
      ),
    enabled: !!selected,
    refetchInterval: (query) =>
      query.state.data?.definition.runs.some((run) => ["queued", "running"].includes(run.execution))
        ? 1000
        : false,
  });
  const history = useQuery({
    queryKey: ["analysis-session-history", selected],
    queryFn: () =>
      api<{ revisions: AnalysisSessionRecord[] }>(
        `/analysis-sessions/${encodeURIComponent(selected!)}/history`,
      ),
    enabled: !!selected && section === "history",
  });
  const record = detail.data;
  // the legacy assessment ids come from the pane (ai/context.tsx)
  const inputSnapshot = record?.definition.input.snapshot?.snapshot;
  useAiContext(useAiPaneId(), {
    section,
    analysis_session: selected
      ? { id: selected, revision: revision ?? record?.revision }
      : undefined,
    snapshot: inputSnapshot ? { id: inputSnapshot, origin: "pinned" } : undefined,
  });
  const drawer = useAiDrawer();
  const openConversation = useOpenConversation();
  // a session saved from a chat step names the conversation it came from
  const origin = (
    record?.results.review as { origin?: { conversation_id?: unknown } } | null | undefined
  )?.origin;
  const chatConversation =
    typeof origin?.conversation_id === "string" ? origin.conversation_id : undefined;
  async function discuss() {
    if (!record || !drawer || !openConversation) return;
    setError("");
    try {
      // a viewer who cannot read that conversation starts one about the session
      if (chatConversation && (await readable(chatConversation)))
        drawer.openConversation(chatConversation);
      else
        await openConversation("assessment_qa", {
          section,
          analysis_session: { id: record.id, revision: record.revision },
          snapshot: inputSnapshot ? { id: inputSnapshot, origin: "pinned" } : undefined,
        });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Conversation not opened");
    }
  }
  const simulation = record?.definition.input.kind === "simulation";
  const simulationResult = record?.results.simulation as Record<string, unknown> | undefined;
  const predicted = hasPrediction(simulationResult);
  const bindings = record?.results.bindings as
    Record<string, { assessment_id: string; assessment_revision: number }> | undefined;
  const admission = record?.results.admission as
    { omitted?: string[]; reason?: string } | undefined;
  const runs = record?.definition.runs ?? [];
  const aggregate = sessionState(runs, simulation ? 0 : (admission?.omitted?.length ?? 0));
  const runRows = runs.map((run) => {
    const binding = bindings?.[run.item_id];
    const chosen = run.id === selectedRun;
    return (
      <div
        key={run.id}
        ref={chosen ? selectedRow : undefined}
        aria-current={chosen ? "true" : undefined}
      >
        <p className="analysis-status">
          <button
            type="button"
            className={chosen ? "on" : "secondary"}
            aria-pressed={chosen}
            onClick={() => selectRun(chosen ? undefined : run.id)}
          >
            {run.item_id}
          </button>
          {simulation && <span>Execution: {run.execution}</span>}
          <span>Coverage: {run.coverage.replace("_", " ")}</span>
        </p>
        {!simulation && <RunResult id={run.id} />}
        {binding && (
          <button
            type="button"
            className="secondary"
            onClick={() => onNavigateLegacy(binding.assessment_id, run.id)}
          >
            Open assessment lifecycle
          </button>
        )}
      </div>
    );
  });
  const retryable =
    !simulation && runs.some((run) => run.execution === "failed" || run.execution === "cancelled");
  const shownRunLoaded = !!selectedRun && runs.some((run) => run.id === selectedRun);
  useEffect(() => {
    if (shownRunLoaded) selectedRow.current?.scrollIntoView?.({ block: "nearest" });
  }, [shownRunLoaded, selectedRun]);
  const omitted =
    !simulation && admission?.omitted?.length ? (
      <section aria-label="Omitted connections">
        <h3>Not submitted</h3>
        <p>{admission.reason}</p>
        <ul>
          {admission.omitted.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
        {canRun && revision == null && (
          <button type="button" disabled={busy} onClick={() => void execute()}>
            {busy ? "Starting" : "Run omitted connections"}
          </button>
        )}
      </section>
    ) : null;
  async function exportRun() {
    if (!record) return;
    setError("");
    try {
      download(
        await apiDownload(
          `/analysis-sessions/${encodeURIComponent(record.id)}/export?revision=${record.revision}`,
        ),
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Run not exported");
    }
  }
  async function execute() {
    if (!record) return;
    setBusy(true);
    setError("");
    try {
      await api(`/analysis-sessions/${encodeURIComponent(record.id)}/runs`, {
        method: "POST",
        body: { session_revision: record.revision, input_digest: record.input_digest },
      });
      setHistorical(undefined);
      setSection("results");
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["analysis-session", record.id] }),
        queryClient.invalidateQueries({ queryKey: ["analysis-sessions"] }),
      ]);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Analysis not started");
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="analysis-workspace">
      <aside className="analysis-session-list">
        <span className="eyebrow">Saved work</span>
        <h2>Analysis</h2>
        {sessions.isLoading && <p role="status">Loading analysis history</p>}
        {sessions.data?.sessions.length === 0 && <p>No sessions</p>}
        <ul>
          {sessions.data?.sessions.map((item) => (
            <li key={item.id}>
              <button
                type="button"
                className={selected === item.id ? "on" : undefined}
                onClick={() => onNavigate(item.id)}
              >
                {item.title}
                <span>
                  {item.definition.input.kind}, revision {item.revision}
                </span>
              </button>
            </li>
          ))}
        </ul>
        {canRun && (
          <button
            type="button"
            onClick={() => {
              onNavigate(undefined);
              setSection("scope");
            }}
          >
            New analysis
          </button>
        )}
      </aside>
      <main className="analysis-session-detail">
        <div className="tabs" role="tablist" aria-label="Analysis sections">
          {(["results", "scope", "history", "verification"] as AnalysisSection[]).map((item) => (
            <button
              key={item}
              role="tab"
              aria-selected={section === item}
              className={section === item ? "on" : undefined}
              onClick={() => setSection(item)}
            >
              {item[0].toUpperCase() + item.slice(1)}
            </button>
          ))}
        </div>
        {legacyAssessmentId && (
          <AssessmentsPage
            key={`${legacyAssessmentId}:${section}`}
            assessmentId={legacyAssessmentId}
            runId={legacyRunId}
            initialSection={section}
            onNavigate={onNavigateLegacy}
          />
        )}
        {legacySimulation && section === "scope" && (
          <ChangeSimPage conversationId={conversationId} onConversation={onConversation} />
        )}
        {!selected && !legacyAssessmentId && !legacySimulation && section === "scope" && canRun && (
          <SimulationBuilder
            onCreated={(id) => {
              void queryClient.invalidateQueries({ queryKey: ["analysis-sessions"] });
              onNavigate(id);
              setSection("results");
            }}
          />
        )}
        {!selected && !legacyAssessmentId && !legacySimulation && section !== "scope" && (
          <div className="application-empty">
            <h3>No analysis selected</h3>
          </div>
        )}
        {record && section === "results" && (
          <section>
            <header className="application-section-heading">
              <div>
                <span className="eyebrow">
                  {record.definition.input.kind}, revision {record.revision}
                </span>
                <h2>{record.title}</h2>
              </div>
              <div className="assessment-actions">
                <button type="button" onClick={() => void exportRun()}>
                  Export run
                </button>
                {openConversation && (
                  <button type="button" onClick={() => void discuss()}>
                    Discuss in HST AI
                  </button>
                )}
              </div>
            </header>
            {runs.length > 0 && (
              <p className="analysis-status">
                <span>Session execution: {aggregate.execution}</span>
                <span>Session coverage: {aggregate.coverage}</span>
              </p>
            )}
            {record.definition.runs.length === 0 && (
              <>
                <p>No run</p>
                {canRun && revision == null && (
                  <button type="button" disabled={busy} onClick={() => void execute()}>
                    {busy ? "Starting" : "Run analysis"}
                  </button>
                )}
              </>
            )}
            {error && <p role="alert">{error}</p>}
            {simulation && record.definition.runs.length > 0 && (
              <SimulationComparison
                result={simulationResult}
                snapshot={record.definition.input.snapshot.snapshot}
              />
            )}
            {runRows}
            {retryable && canRun && revision == null && (
              <button type="button" disabled={busy} onClick={() => void execute()}>
                {busy ? "Starting" : "Run failed and cancelled connections again"}
              </button>
            )}
            {omitted}
            {Array.isArray(record.results.protected) && record.results.protected.length > 0 && (
              <section>
                <h3>Protected requirements</h3>
                <pre>{JSON.stringify(record.results.protected, null, 2)}</pre>
              </section>
            )}
          </section>
        )}
        {record && section === "scope" && (
          <section>
            <h2>Scope</h2>
            <pre>{JSON.stringify(record.definition.input, null, 2)}</pre>
            {record.results.review != null && (
              <>
                <h3>Selections</h3>
                <pre>{JSON.stringify(record.results.review, null, 2)}</pre>
              </>
            )}
          </section>
        )}
        {record && section === "history" && (
          <section>
            <h2>History</h2>
            {revision != null && (
              <button type="button" onClick={() => setHistorical(undefined)}>
                Return to current revision
              </button>
            )}
            {history.isLoading && <p role="status">Loading history</p>}
            {history.data?.revisions.map((item) => (
              <article className="application-row" key={item.revision}>
                <strong>Revision {item.revision}</strong>
                <span>{new Date(item.created_at).toLocaleString()}</span>
                <span>{item.definition.runs.length ? "Execution recorded" : "Reviewed input"}</span>
                <button
                  type="button"
                  onClick={() => {
                    setHistorical({ sessionId: record.id, revision: item.revision });
                    setSection("results");
                  }}
                >
                  Open revision
                </button>
              </article>
            ))}
            {sessions.data && (
              <SessionRunComparison sessionId={record.id} sessions={sessions.data.sessions} />
            )}
          </section>
        )}
        {record && section === "verification" && (
          <section>
            <h2>Verification</h2>
            {simulation ? (
              predicted ? null : (
                <p>No prediction</p>
              )
            ) : (
              <>
                {Object.entries(bindings ?? {}).map(([itemId, binding]) => (
                  <button
                    type="button"
                    key={itemId}
                    onClick={() => onNavigateLegacy(binding.assessment_id)}
                  >{`Open deployment and verification for ${itemId}`}</button>
                ))}
              </>
            )}
          </section>
        )}
      </main>
    </div>
  );
}
