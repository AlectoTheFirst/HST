import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, apiDownload } from "../api/client";
import { atLeast, useAuth } from "../auth";
import { AnalysisForm } from "./AnalysisForm";
import { AnalysisResult, EvidenceValue, record } from "./AnalysisResult";
import { AssessmentEditor } from "./AssessmentEditor";
import { WorkflowChoices, workflowTitle } from "./WorkflowChoices";
import { AssistantDraftPanel } from "./AssistantDraftPanel";
import { PinnedSnapshotPicker } from "./PinnedSnapshotPicker";
import { Field } from "./RequirementComposer";
import {
  CollectionFollowup,
  RetentionPanel,
  RunComparison,
  proposalSummary,
} from "./LifecyclePanels";
import { ProposalPanel } from "./ProposalPanel";
import { RevisionHistory } from "./RevisionHistory";
import { conditionSentence, emptyRequirement, isRunning } from "./types";
import type {
  AnalysisRun,
  Assessment,
  AssessmentDetail,
  AssessmentDraft,
  Definition,
  AnalysisKind,
} from "./types";
import type { AnalysisSection } from "../analysis/contracts";
import { useAiContext, useAiPaneId } from "../ai/context";
import { useOpenConversation } from "../ai/drawer";
import "./assessments.css";

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
/** The run a saved analysis was computed on: its first snapshot reference. */
function runSnapshot(run: AnalysisRun | undefined): string | undefined {
  const refs = run?.inputs.snapshot_refs;
  const value = Array.isArray(refs) ? record(refs[0]).snapshot : undefined;
  return typeof value === "string" || typeof value === "number" ? String(value) : undefined;
}
function date(value: string): string {
  return new Date(value).toLocaleString();
}
/** The engine build a run recorded, as the short commit inside its version string. */
function engineBuild(version: unknown): string {
  const parts = typeof version === "string" ? version.split(":") : [];
  return parts.length > 1 && parts[1] ? parts[1].slice(0, 12) : "unknown";
}
function failureExplanation(item: AnalysisRun): string | null {
  const runtime = record(record(item.result).runtime_exception);
  if (item.state !== "failed" || !runtime.kind) return null;
  const where = [
    runtime.file ? `in ${String(runtime.file)}` : "",
    runtime.function ? `function ${String(runtime.function)}` : "",
    runtime.line !== undefined ? `line ${String(runtime.line)}` : "",
  ]
    .filter(Boolean)
    .join(", ");
  return `Engine build ${engineBuild(item.engine_version)} stopped with ${String(runtime.kind)}${where ? ` ${where}` : ""}`;
}
function download(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function RunDetail({
  assessment,
  runId,
  canOperate,
  onRefresh,
  onRetry,
  selectedFindingId,
  onSelectFinding,
}: {
  assessment: Assessment;
  runId: string;
  canOperate: boolean;
  onRefresh: () => void;
  onRetry: (inputs: Record<string, unknown>) => void;
  selectedFindingId?: string | null;
  onSelectFinding?: (findingId: string | null, findingRef?: string) => void;
}) {
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [selectedActions, setSelectedActions] = useState<string[]>([]);
  const run = useQuery({
    queryKey: ["analysis-job", runId],
    queryFn: () => api<AnalysisRun>(`/analysis-jobs/${encodeURIComponent(runId)}`),
    refetchInterval: (query) =>
      query.state.data && isRunning(query.state.data.state) ? 1000 : false,
  });
  const openConversation = useOpenConversation();
  async function perform(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await action();
    } catch (e) {
      setError(message(e));
    } finally {
      setBusy(false);
    }
  }
  const item = run.data;
  // a chat about one finding of this run, with the run's snapshot
  const snapshot = runSnapshot(item);
  const askAi = openConversation
    ? (finding: string) =>
        void perform(async () => {
          await openConversation("assessment_qa", {
            section: "results",
            assessment: {
              assessment_id: assessment.id,
              revision: assessment.revision,
              run_id: runId,
              finding_id: finding,
            },
            snapshot: snapshot ? { id: snapshot, origin: "pinned" } : undefined,
          });
        })
    : undefined;
  const actions = Array.isArray(item?.result?.actions) ? item.result.actions.map(record) : [];
  const explanation = item ? failureExplanation(item) : null;
  return (
    <section className="assessment-run" aria-label="Saved analysis run">
      {run.isLoading && <p role="status">Loading saved run</p>}
      {run.isError && <p role="alert">{message(run.error)}</p>}
      {item && (
        <>
          <header className="assessment-run-header">
            <div>
              <h3>
                {item.kind.charAt(0).toUpperCase()}
                {item.kind.slice(1)} analysis
              </h3>
              <p role="status">
                Job: {item.state}, created {date(item.created_at)}
              </p>
            </div>
            <dl>
              <div>
                <dt>Run</dt>
                <dd>{item.id}</dd>
              </div>
              <div>
                <dt>Assessment revision</dt>
                <dd>
                  {item.assessment_revision ?? "Not recorded"}
                  {item.assessment_revision && item.assessment_revision !== assessment.revision
                    ? ` (current is ${assessment.revision})`
                    : ""}
                </dd>
              </div>
              <div>
                <dt>Snapshot</dt>
                <dd>
                  {String(
                    (Array.isArray(item.inputs.snapshot_refs)
                      ? record(item.inputs.snapshot_refs[0]).snapshot
                      : undefined) ??
                      item.inputs.snapshot ??
                      record(item.inputs.definition).snapshot ??
                      "Not recorded",
                  )}
                </dd>
              </div>
              <div>
                <dt>Engine</dt>
                <dd>{engineBuild(item.engine_version)}</dd>
              </div>
            </dl>
          </header>
          {item.progress && (
            <details>
              <summary>Execution progress</summary>
              <EvidenceValue value={item.progress} />
            </details>
          )}
          <div className="assessment-actions">
            {isRunning(item.state) && canOperate && (
              <button
                type="button"
                disabled={busy || item.state === "cancelling"}
                onClick={() =>
                  perform(async () => {
                    await api(`/analysis-jobs/${encodeURIComponent(runId)}/cancel`, {
                      method: "POST",
                    });
                    await run.refetch();
                    onRefresh();
                  })
                }
              >
                Cancel analysis
              </button>
            )}
            {!isRunning(item.state) && (
              <button
                type="button"
                disabled={busy}
                onClick={() =>
                  perform(async () => {
                    const file = await apiDownload(
                      `/assessments/${encodeURIComponent(assessment.id)}/runs/${encodeURIComponent(runId)}/export`,
                    );
                    download(file.blob, file.filename);
                  })
                }
              >
                Export exact run
              </button>
            )}
            {canOperate && !!item.result && !isRunning(item.state) && (
              <button
                type="button"
                disabled={busy}
                onClick={() =>
                  perform(async () => {
                    const file = await apiDownload(
                      `/assessments/${encodeURIComponent(assessment.id)}/runs/${encodeURIComponent(runId)}/export?portable=true`,
                      { fallbackFilename: `assessment-${runId}.zip` },
                    );
                    download(file.blob, file.filename);
                  })
                }
              >
                Export evidence package
              </button>
            )}
            {canOperate &&
              ["failed", "cancelled"].includes(item.state) &&
              !!record(item.inputs.analysis).kind && (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => onRetry({ ...record(item.inputs.analysis), retry_of: item.id })}
                >
                  Retry with current revision
                </button>
              )}
            <a
              href={`/?assessment=${encodeURIComponent(assessment.id)}&assessment_run=${encodeURIComponent(runId)}`}
            >
              Link to this run
            </a>
          </div>
          {!!item.error && (
            <div role="alert">
              <EvidenceValue value={item.error} />
            </div>
          )}
          {explanation && <p className="assessment-gaps">{explanation}</p>}
          {item.result && (
            <AnalysisResult
              result={item.result}
              analysisKind={item.kind}
              selectedFindingId={selectedFindingId}
              onSelectFinding={onSelectFinding}
              onAskAi={askAi}
              loadBucket={
                record(item.result.symbolic).artifact_ref
                  ? (bucket, offset) =>
                      api(
                        `/assessments/${encodeURIComponent(assessment.id)}/runs/${encodeURIComponent(runId)}/buckets?bucket=${encodeURIComponent(bucket)}&offset=${encodeURIComponent(offset)}`,
                      )
                  : undefined
              }
              onSaveProposal={
                canOperate
                  ? (findingIndex) =>
                      perform(async () => {
                        const saved = await api(
                          `/assessments/${encodeURIComponent(assessment.id)}/runs/${encodeURIComponent(runId)}/proposals`,
                          {
                            method: "POST",
                            body: {
                              finding_index: findingIndex,
                              title: `${assessment.title} proposal ${findingIndex + 1}`,
                            },
                          },
                        );
                        setNotice(proposalSummary(saved));
                        onRefresh();
                      })
                  : undefined
              }
            />
          )}
          {actions.length > 0 && (
            <section>
              <h3>Suggested collection actions</h3>
              {actions.map((action, i) => (
                <fieldset key={String(action.id ?? i)}>
                  <legend>Collection action {i + 1}</legend>
                  <label className="assessment-check">
                    <input
                      type="checkbox"
                      disabled={!canOperate || action.state !== "available"}
                      checked={selectedActions.includes(String(action.id))}
                      onChange={(e) =>
                        setSelectedActions(
                          e.target.checked
                            ? [...selectedActions, String(action.id)]
                            : selectedActions.filter((id) => id !== action.id),
                        )
                      }
                    />
                    Select {String(action.recipe_id ?? action.id)}
                  </label>
                  <EvidenceValue value={action} />
                </fieldset>
              ))}
              <button
                type="button"
                disabled={!canOperate || busy || !selectedActions.length}
                onClick={() =>
                  perform(async () => {
                    await api(
                      `/assessments/${encodeURIComponent(assessment.id)}/collection-actions`,
                      { method: "POST", body: { run_id: runId, action_ids: selectedActions } },
                    );
                    setNotice("Collection queued");
                    setSelectedActions([]);
                    onRefresh();
                  })
                }
              >
                Collect selected evidence
              </button>
            </section>
          )}
        </>
      )}
      {error && <p role="alert">{error}</p>}
      {notice && <p role="status">{notice}</p>}
    </section>
  );
}

export default function AssessmentsPage({
  assessmentId,
  runId,
  draft,
  initialSection = "results",
  onNavigate,
}: {
  assessmentId?: string;
  runId?: string;
  draft?: AssessmentDraft;
  initialSection?: AnalysisSection | "evidence";
  onNavigate: (assessmentId?: string, runId?: string) => void;
}) {
  const { user } = useAuth();
  const canOperate = !!user && atLeast(user.role, "operator");
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState(!!draft);
  const [activeDraft, setActiveDraft] = useState(draft);
  const [draftVersion, setDraftVersion] = useState(0);
  const [assistantSnapshot, setAssistantSnapshot] = useState(draft?.definition.snapshot ?? "");
  const [analysisKind, setAnalysisKind] = useState<AnalysisKind | null>(null);
  const [analysisOwner, setAnalysisOwner] = useState<string | undefined>();
  const [analysisInput, setAnalysisInput] = useState<Record<string, unknown>>({});
  const [showAnalysisSetup, setShowAnalysisSetup] = useState(false);
  const [findingSelection, setFindingSelection] = useState<Record<string, string | null>>({});
  // the reference the server resolves for each run's selected finding
  const [findingRefs, setFindingRefs] = useState<Record<string, string | undefined>>({});
  const [verifyLibrary, setVerifyLibrary] = useState(false);
  const [showFailed, setShowFailed] = useState(false);
  const [stateFilter, setStateFilter] = useState("");
  const [filter, setFilter] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [tab, setTab] = useState<AnalysisSection | "evidence">(initialSection);
  const [reference, setReference] = useState("");
  const [deployedAt, setDeployedAt] = useState("");
  const library = useQuery({
    queryKey: ["assessments"],
    queryFn: () =>
      api<{ assessments: Assessment[]; evidence_portfolio?: Record<string, unknown> }>(
        "/assessments?include_evidence=true",
      ),
  });
  const detail = useQuery({
    queryKey: ["assessment", assessmentId],
    enabled: !!assessmentId,
    queryFn: () => api<AssessmentDetail>(`/assessments/${encodeURIComponent(assessmentId!)}`),
    refetchInterval: (query) =>
      query.state.data?.runs.some((run) => isRunning(run.state)) ? 1500 : false,
  });
  const assessment = detail.data?.assessment;
  function refreshOf(id: string | undefined) {
    void queryClient.invalidateQueries({ queryKey: ["assessment", id] });
    void queryClient.invalidateQueries({ queryKey: ["assessments"] });
  }
  function refresh() {
    refreshOf(assessmentId);
  }
  async function perform(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await action();
    } catch (e) {
      setError(message(e));
    } finally {
      setBusy(false);
    }
  }
  function openDraft(next: AssessmentDraft) {
    setActiveDraft(next);
    setDraftVersion((v) => v + 1);
    setEditing(true);
    setError("");
    onNavigate();
  }
  function newWorkflow(kind: AnalysisKind) {
    if (kind === "verify") {
      setStateFilter("");
      setFilter("");
      setVerifyLibrary(true);
      setError("");
      return;
    }
    openDraft({
      title: "",
      definition: {
        request: emptyRequirement(),
        intents: [],
        mode: "possible",
        snapshot: assistantSnapshot,
        freshness_s: 86400,
      },
      kind,
    });
  }
  function save(title: string, definition: Definition, analysis?: Record<string, unknown>) {
    void perform(async () => {
      const saved = await api<Assessment>(
        assessment ? `/assessments/${encodeURIComponent(assessment.id)}` : "/assessments",
        {
          method: assessment ? "PATCH" : "POST",
          body: {
            title,
            definition,
            ...(assessment ? { expected_revision: assessment.revision } : {}),
          },
        },
      );
      setEditing(false);
      refreshOf(saved.id);
      onNavigate(saved.id);
      if (analysis) {
        setAnalysisKind(analysis.kind as AnalysisKind);
        setAnalysisInput(analysis);
        setAnalysisOwner(saved.id);
        const run = await api<AnalysisRun>(
          `/assessments/${encodeURIComponent(saved.id)}/analyses`,
          { method: "POST", body: analysis },
        );
        setTab("results");
        setShowAnalysisSetup(false);
        refreshOf(saved.id);
        onNavigate(saved.id, run.id);
      }
      setActiveDraft(undefined);
    });
  }
  function start(input: Record<string, unknown>) {
    if (!assessment) return;
    void perform(async () => {
      const run = await api<AnalysisRun>(
        `/assessments/${encodeURIComponent(assessment.id)}/analyses`,
        { method: "POST", body: input },
      );
      setTab("results");
      setShowAnalysisSetup(false);
      refresh();
      onNavigate(assessment.id, run.id);
    });
  }
  const selectedRun = runId ?? detail.data?.runs[0]?.id;
  const runs = detail.data?.runs ?? [];
  const failedRuns = runs.filter((run) => run.state === "failed");
  const freshness = detail.data?.freshness;
  const freshnessCauses = freshness?.causes ?? freshness?.reasons ?? [];
  const shownSnapshot =
    runSnapshot(runs.find((run) => run.id === selectedRun)) ?? assessment?.definition.snapshot;
  useAiContext(
    useAiPaneId(),
    assessmentId
      ? {
          section: tab,
          assessment: {
            assessment_id: assessmentId,
            revision: assessment?.revision,
            run_id: selectedRun,
            finding_id:
              (selectedRun && findingSelection[selectedRun] && findingRefs[selectedRun]) ||
              undefined,
          },
          snapshot: shownSnapshot ? { id: shownSnapshot, origin: "pinned" } : undefined,
        }
      : null,
  );
  return (
    <div className="assessments-page">
      <header className="assessment-heading">
        <div>
          <h2>Assessments</h2>
        </div>
        <div className="assessment-actions">
          {assessmentId && (
            <button
              type="button"
              onClick={() => {
                setEditing(false);
                onNavigate();
              }}
            >
              Open assessment library
            </button>
          )}
          {canOperate && !editing && (
            <button
              type="button"
              onClick={() => {
                onNavigate();
                setActiveDraft(undefined);
                setDraftVersion((v) => v + 1);
                setEditing(true);
              }}
            >
              New assessment
            </button>
          )}
        </div>
      </header>
      {error && <p role="alert">{error}</p>}
      {editing ? (
        <AssessmentEditor
          key={`${assessment?.id ?? "new"}:${draftVersion}`}
          initial={assessment}
          draft={activeDraft}
          busy={busy}
          onSave={save}
          onCancel={() => setEditing(false)}
        />
      ) : assessmentId ? (
        <>
          {detail.isLoading && <p role="status">Loading assessment</p>}
          {detail.isError && <p role="alert">{message(detail.error)}</p>}
          {assessment && (
            <>
              <div className="assessment-context">
                <h2>{assessment.title}</h2>
                <p>
                  Revision {assessment.revision}, snapshot {assessment.definition.snapshot},{" "}
                  {assessment.definition.mode} forwarding
                </p>
                {freshness && (
                  <p className={freshness.state === "current" ? "" : "assessment-gaps"}>
                    {freshness.state.replaceAll("_", " ")}
                    {freshnessCauses.length
                      ? `: ${freshnessCauses.map((reason) => (typeof reason === "string" ? reason : String(record(reason).kind ?? record(reason).reason ?? "Evidence changed"))).join(", ")}`
                      : ""}
                  </p>
                )}
                {assessment.definition.request && (
                  <p>{conditionSentence(assessment.definition.request.condition)}</p>
                )}
                <div className="assessment-actions">
                  {canOperate && (
                    <button
                      type="button"
                      onClick={() => {
                        setActiveDraft(undefined);
                        setEditing(true);
                      }}
                    >
                      Edit assessment
                    </button>
                  )}
                  <a href={`/?assessment=${encodeURIComponent(assessment.id)}`}>
                    Permanent assessment link
                  </a>
                </div>
              </div>
              <div className="assessment-tabs" role="group" aria-label="Assessment sections">
                {(
                  [
                    ["Results", "results"],
                    ["Scope", "scope"],
                    ["History", "history"],
                    ["Verification", "verification"],
                    ["Evidence", "evidence"],
                  ] as [string, AnalysisSection | "evidence"][]
                ).map(([name, value]) => (
                  <button
                    type="button"
                    key={value}
                    aria-pressed={tab === value}
                    onClick={() => setTab(value)}
                  >
                    {name}
                  </button>
                ))}
              </div>
              {tab === "results" && (
                <>
                  <div className="assessment-actions">
                    {canOperate && (
                      <button
                        type="button"
                        onClick={() => {
                          setTab("scope");
                          setShowAnalysisSetup(true);
                        }}
                      >
                        Run analysis
                      </button>
                    )}
                  </div>
                  <h3>Saved runs</h3>
                  {!runs.length && <p>No analyses</p>}
                  {failedRuns.length > 0 && (
                    <label className="assessment-check">
                      <input
                        type="checkbox"
                        checked={showFailed}
                        onChange={(e) => setShowFailed(e.target.checked)}
                      />
                      Show {failedRuns.length} failed {failedRuns.length === 1 ? "run" : "runs"}
                    </label>
                  )}
                  <div className="assessment-run-list">
                    {runs
                      .filter(
                        (run) => showFailed || run.state !== "failed" || run.id === selectedRun,
                      )
                      .map((run) => (
                        <button
                          key={run.id}
                          type="button"
                          aria-pressed={run.id === selectedRun}
                          onClick={() => onNavigate(assessment.id, run.id)}
                        >
                          {run.kind} / {run.state} / {date(run.created_at)}
                        </button>
                      ))}
                  </div>
                  {selectedRun && (
                    <RunDetail
                      key={selectedRun}
                      assessment={assessment}
                      runId={selectedRun}
                      canOperate={canOperate}
                      onRefresh={refresh}
                      onRetry={start}
                      selectedFindingId={findingSelection[selectedRun]}
                      onSelectFinding={(findingId, findingRef) => {
                        setFindingSelection((value) => ({ ...value, [selectedRun]: findingId }));
                        setFindingRefs((value) => ({ ...value, [selectedRun]: findingRef }));
                      }}
                    />
                  )}
                </>
              )}
              {tab === "scope" && (
                <>
                  <h3>Assessment scope</h3>
                  <EvidenceValue
                    value={
                      selectedRun
                        ? (runs.find((run) => run.id === selectedRun)?.inputs ??
                          assessment.definition)
                        : assessment.definition
                    }
                  />
                  {canOperate && !showAnalysisSetup && (
                    <button type="button" onClick={() => setShowAnalysisSetup(true)}>
                      Run analysis
                    </button>
                  )}
                  {canOperate && showAnalysisSetup && (
                    <section>
                      <h3>Question</h3>
                      <WorkflowChoices
                        onChoose={(kind) => {
                          if (kind === "verify") setTab("verification");
                          else {
                            setAnalysisKind(kind);
                            setAnalysisInput({});
                            setAnalysisOwner(assessment.id);
                          }
                        }}
                        selected={
                          analysisOwner === assessment.id ? (analysisKind ?? undefined) : undefined
                        }
                      />
                      {analysisKind && analysisOwner === assessment.id && (
                        <section aria-label={workflowTitle(analysisKind)}>
                          <AnalysisForm
                            key={`${assessment.id}:${assessment.revision}:${analysisKind}`}
                            assessment={assessment}
                            busy={busy}
                            initialKind={analysisKind}
                            initialInput={analysisInput}
                            onSubmit={start}
                          />
                          <button
                            type="button"
                            onClick={() => {
                              setAnalysisKind(null);
                              setShowAnalysisSetup(false);
                            }}
                          >
                            Close analysis setup
                          </button>
                        </section>
                      )}
                    </section>
                  )}
                </>
              )}
              {tab === "history" && (
                <>
                  <ProposalPanel
                    proposals={detail.data?.proposals ?? []}
                    assessment={assessment}
                    canOperate={canOperate}
                    onRefresh={refresh}
                    onEvaluate={(definition, protectedRequirements) => {
                      void perform(async () => {
                        const saved = await api<Assessment>(
                          `/assessments/${encodeURIComponent(assessment.id)}`,
                          {
                            method: "PATCH",
                            body: {
                              title: assessment.title,
                              definition,
                              expected_revision: assessment.revision,
                            },
                          },
                        );
                        const run = await api<AnalysisRun>(
                          `/assessments/${encodeURIComponent(saved.id)}/analyses`,
                          {
                            method: "POST",
                            body: { kind: "evaluate", protected: protectedRequirements },
                          },
                        );
                        setTab("results");
                        refresh();
                        onNavigate(saved.id, run.id);
                      });
                    }}
                  />
                  <RunComparison runs={runs} />
                  <RevisionHistory
                    key={`${assessment.id}:${assessment.revision}`}
                    assessment={assessment}
                  />
                </>
              )}
              {tab === "evidence" && (
                <>
                  <CollectionFollowup assessment={assessment} onNavigate={onNavigate} />
                  <RetentionPanel
                    assessment={assessment}
                    runId={selectedRun}
                    canAdminister={user?.role === "admin"}
                  />
                </>
              )}
              {tab === "verification" && (
                <>
                  <h3>Deployment and verification</h3>
                  <EvidenceValue
                    value={detail.data?.deployments ?? assessment.definition.deployments ?? []}
                  />
                  {canOperate && (
                    <>
                      <form
                        onSubmit={(e) => {
                          e.preventDefault();
                          void perform(async () => {
                            await api(
                              `/assessments/${encodeURIComponent(assessment.id)}/deployments`,
                              {
                                method: "POST",
                                body: {
                                  reference,
                                  deployed_at: new Date(deployedAt).toISOString(),
                                  assessment_revision: assessment.revision,
                                },
                              },
                            );
                            setReference("");
                            refresh();
                          });
                        }}
                      >
                        <div className="assessment-fields">
                          <Field
                            label="Deployment reference"
                            value={reference}
                            required
                            onChange={setReference}
                          />
                          <Field
                            label="Deployment time"
                            type="datetime-local"
                            value={deployedAt}
                            required
                            onChange={setDeployedAt}
                          />
                        </div>
                        <button type="submit" disabled={busy}>
                          Record deployment
                        </button>
                      </form>
                      <AnalysisForm
                        key={`verify:${assessment.id}:${assessment.revision}`}
                        assessment={assessment}
                        busy={busy}
                        onSubmit={start}
                        initialKind="verify"
                      />
                    </>
                  )}
                </>
              )}
            </>
          )}
        </>
      ) : (
        <>
          {canOperate && (
            <section className="assessment-start">
              <h2>Question</h2>
              <WorkflowChoices onChoose={newWorkflow} />
              <details>
                <summary>AI draft</summary>
                <PinnedSnapshotPicker
                  label="AI draft snapshot"
                  value={assistantSnapshot}
                  onChange={setAssistantSnapshot}
                />
                <AssistantDraftPanel
                  key={assistantSnapshot}
                  snapshot={assistantSnapshot}
                  onDraft={openDraft}
                />
              </details>
            </section>
          )}
          <h2>{verifyLibrary ? "Deployed assessments" : "Saved assessments"}</h2>
          {verifyLibrary && (
            <p>
              <button type="button" onClick={() => setVerifyLibrary(false)}>
                Show all assessments
              </button>
            </p>
          )}
          <div className="assessment-fields">
            <Field label="Filter assessments" value={filter} onChange={setFilter} />
            <label className="assessment-field">
              <span>Evidence state</span>
              <select value={stateFilter} onChange={(e) => setStateFilter(e.target.value)}>
                <option value="">All states</option>
                {(
                  [
                    ["current", "Current"],
                    ["needs-reassessment", "Needs reassessment"],
                    ["unevaluated", "Unevaluated"],
                  ] as const
                ).map(([state, stateName]) => (
                  <option key={state} value={state}>
                    {stateName}
                  </option>
                ))}
              </select>
            </label>
          </div>
          {Array.isArray(library.data?.evidence_portfolio?.actions) &&
            library.data.evidence_portfolio.actions.length > 0 && (
              <section>
                <h2>Evidence priorities across assessments</h2>
                {library.data.evidence_portfolio.actions.map((value, index) => {
                  const action = record(value);
                  const origins = Array.isArray(action.origins) ? action.origins.map(record) : [];
                  return (
                    <details key={String(action.id ?? index)}>
                      <summary>
                        {String(action.source)} / {String(action.host || "controller")} / priority{" "}
                        {String(action.priority)}
                      </summary>
                      <EvidenceValue value={action} />
                      {origins.map((origin, i) => (
                        <button
                          type="button"
                          key={i}
                          onClick={() =>
                            onNavigate(String(origin.assessment_id), String(origin.run_id))
                          }
                        >
                          Review affected assessment {String(origin.assessment_id)}
                        </button>
                      ))}
                    </details>
                  );
                })}
              </section>
            )}
          {library.isLoading && <p role="status">Loading assessments</p>}
          {library.isError && <p role="alert">{message(library.error)}</p>}
          {library.data && !library.data.assessments.length && <p>No saved assessments</p>}
          {verifyLibrary &&
            library.data &&
            !library.data.assessments.some((item) => item.definition.deployments?.length) && (
              <p>No recorded deployments</p>
            )}
          <div className="assessment-library">
            {library.data?.assessments
              .filter(
                (item) =>
                  item.title.toLowerCase().includes(filter.toLowerCase()) &&
                  (!stateFilter || item.freshness?.state === stateFilter) &&
                  (!verifyLibrary || !!item.definition.deployments?.length),
              )
              .map((item) => (
                <button
                  type="button"
                  key={item.id}
                  onClick={() => {
                    if (verifyLibrary) setTab("verification");
                    onNavigate(item.id);
                  }}
                >
                  <strong>{item.title}</strong>
                  <span>
                    Revision {item.revision}, {item.definition.mode} forwarding
                  </span>
                  <span>Snapshot {item.definition.snapshot}</span>
                  <span>
                    {item.freshness?.state ?? "unevaluated"}, priority{" "}
                    {item.definition.priority ?? 1}
                  </span>
                </button>
              ))}
          </div>
        </>
      )}
    </div>
  );
}
