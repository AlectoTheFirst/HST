/**
 * The tool steps of one answer as result cards: in the HST AI drawer
 * (shell/AgentDrawer.tsx) and, in the compact variant, under the
 * change-simulation chat (changesim/ChatPanel.tsx).
 *
 * The cards of one answer sit behind one disclosure. Each card shows the
 * step's label, such as `s3`, and its tool, and is the element the citation
 * chips open (ai/citations.tsx). A `change_simulate` or
 * `impact_evaluate_service` result that the pane parsers read
 * (changesim/assessImpact.ts) gets a summary line, and its arguments and
 * result text sit behind a second disclosure. Any other step shows its
 * arguments and result text; the compact variant puts them behind the
 * second disclosure too.
 *
 * The handoffs send the id of
 * the stored step and nothing else; the server reads the rest from the step.
 * - "Save as simulation", on a `change_simulate` step and for a user with
 *   `changes.write`, saves the step as an analysis session
 *   (POST /api/ai/steps/{id}/analysis-session) and opens it in the focused
 *   pane. It is the only way a chat creates a durable simulation record. A
 *   step that the conversation's links name as saved shows "Open analysis
 *   session" in its place.
 * - "Investigate evidence", on an `impact_evaluate_service` step, opens the
 *   assessment draft the server builds for the step
 *   (GET /api/ai/steps/{id}/assessment-draft). The compact variant leaves it
 *   out.
 * - A `change_simulate` card of a stored conversation moves the conversation
 *   to the other chat: "Open in Change simulation" in the drawer opens it in
 *   the focused pane (the `open-changesim` workspace action), and "Open in
 *   drawer" in the compact variant opens it in the HST AI drawer.
 *
 * An action on the focused pane first navigates to the workspace route when
 * the drawer is open on another route.
 */

import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import type { AgentStep, AiConversation } from "../api/types";
import type { AnalysisSessionRecord } from "../analysis/contracts";
import type { AssessmentDraft } from "../assessments/types";
import { useCurrentUser } from "../auth";
import {
  parseChangeSimulate,
  parseImpactEvaluateService,
  resultsNotEstablished,
  type EvaluateServiceImpactResult,
  type ServiceImpactBucket,
  type SimulatePolicyChangeResult,
} from "../changesim/assessImpact";
import { useOpenInWorkspace } from "../workspace/WorkspaceContext";
import { stepElementId } from "./citations";
import { useAiDrawer } from "./drawer";

/** A step of a turn. A stored step carries its id and its label. */
export type CardStep = AgentStep & { id?: string; step?: string };

/** The tool whose step saves as an analysis session. */
const SIMULATION_TOOL = "change_simulate";
/** The tool whose step has an assessment draft. */
const SERVICE_TOOL = "impact_evaluate_service";

function stepPath(stepId: string, handoff: "analysis-session" | "assessment-draft"): string {
  return `/ai/steps/${encodeURIComponent(stepId)}/${handoff}`;
}

/** Save a stored `change_simulate` step as an analysis session. */
export function saveStepSimulation(stepId: string): Promise<AnalysisSessionRecord> {
  return api<AnalysisSessionRecord>(stepPath(stepId, "analysis-session"), { method: "POST" });
}

/** The assessment draft of a stored `impact_evaluate_service` step. */
export function stepAssessmentDraft(stepId: string): Promise<AssessmentDraft> {
  return api<AssessmentDraft>(stepPath(stepId, "assessment-draft"));
}

function errorText(cause: unknown, fallback: string): string {
  return cause instanceof Error && cause.message ? cause.message : fallback;
}

function counted(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

function bucketCount(bucket: ServiceImpactBucket): string {
  return bucket.count != null ? String(bucket.count) : (bucket.count_decimal ?? "not known");
}

export function simulationSummary(result: SimulatePolicyChangeResult): string {
  const notEstablished = resultsNotEstablished(result);
  return [
    counted(result.flow_count, "flow traced", "flows traced"),
    `${result.results_changed} with a changed result`,
    notEstablished > 0 ? `${notEstablished} with a comparison not established` : "",
    result.path_count_after != null
      ? `${result.paths_blocked_after ?? 0} of ${result.path_count_after} paths blocked after the change`
      : "",
    result.snapshot ? `run ${result.snapshot}` : "",
  ]
    .filter(Boolean)
    .join(", ");
}

function serviceSummary(result: EvaluateServiceImpactResult): string {
  return [
    result.request.name,
    result.mode,
    `fails after the change ${bucketCount(result.decided_change.loss)}`,
    `may fail after the change ${bucketCount(result.open_change.loss)}`,
    `not decided after the change ${bucketCount(result.open.after)}`,
    result.snapshot ? `run ${result.snapshot}` : "",
  ]
    .filter(Boolean)
    .join(", ");
}

/** The summary line of a result a pane parser reads, or null. */
function summary(step: CardStep): string | null {
  if (step.is_error) return null;
  if (step.name === SIMULATION_TOOL) {
    const result = parseChangeSimulate(step.result);
    return result ? simulationSummary(result) : null;
  }
  if (step.name === SERVICE_TOOL) {
    const result = parseImpactEvaluateService(step.result);
    return result ? serviceSummary(result) : null;
  }
  return null;
}

function Raw({ step }: { step: CardStep }) {
  return (
    <>
      <pre className="rawpre">{JSON.stringify(step.arguments, null, 1)}</pre>
      <pre className="rawpre">{step.result}</pre>
    </>
  );
}

/** The query key of the conversation read that carries its links. */
function conversationKey(conversationId: string | undefined): unknown[] {
  return ["ai-conversation", conversationId];
}

/** "Save as simulation": saves the step, then opens the saved session. A step
 *  the conversation's links already name as saved opens that session. */
function SaveSimulation({ stepId, conversationId }: { stepId: string; conversationId?: string }) {
  const openIn = useOpenInWorkspace();
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState<AnalysisSessionRecord>();
  const conversation = useQuery({
    queryKey: conversationKey(conversationId),
    queryFn: () => api<AiConversation>(`/ai/conversations/${encodeURIComponent(conversationId!)}`),
    enabled: !!conversationId,
  });
  const linked = conversation.data?.links?.find(
    (link) => link.kind === "analysis_session" && link.direction === "to" && link.step_id === stepId,
  );
  const sessionId = saved?.id ?? linked?.ref_id;

  async function save() {
    setBusy(true);
    setError("");
    try {
      const record = await saveStepSimulation(stepId);
      setSaved(record);
      void queryClient.invalidateQueries({ queryKey: ["analysis-sessions"] });
      if (conversationId) void queryClient.invalidateQueries({ queryKey: conversationKey(conversationId) });
      openIn?.((workspace) => workspace.openAnalysis(record.id, "simulation"));
    } catch (cause) {
      setError(errorText(cause, "Simulation not saved"));
    } finally {
      setBusy(false);
    }
  }

  if (sessionId !== undefined) {
    return (
      <>
        <span className="result-card-note" role="status">
          {saved ? <>Saved as analysis session {saved.title}</> : "Saved as analysis session"}
        </span>
        {openIn && (
          <button
            type="button"
            className="linkish"
            onClick={() => openIn((workspace) => workspace.openAnalysis(sessionId, "simulation"))}
          >
            Open analysis session
          </button>
        )}
      </>
    );
  }
  return (
    <>
      <button type="button" className="linkish" disabled={busy} onClick={() => void save()}>
        {busy ? "Saving" : "Save as simulation"}
      </button>
      {error && (
        <span className="result-card-note bad" role="alert">
          {error}
        </span>
      )}
    </>
  );
}

/** "Investigate evidence": opens the assessment draft of the step. */
function InvestigateEvidence({ stepId }: { stepId: string }) {
  const openIn = useOpenInWorkspace();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function open() {
    setBusy(true);
    setError("");
    try {
      const draft = await stepAssessmentDraft(stepId);
      openIn?.((workspace) => workspace.openAssessments(undefined, undefined, draft));
    } catch (cause) {
      setError(errorText(cause, "Assessment draft not built"));
    } finally {
      setBusy(false);
    }
  }

  if (!openIn) return null;
  return (
    <>
      <button type="button" className="linkish" disabled={busy} onClick={() => void open()}>
        Investigate evidence
      </button>
      {error && (
        <span className="result-card-note bad" role="alert">
          {error}
        </span>
      )}
    </>
  );
}

function ResultCard({ step, compact, conversationId }: { step: CardStep; compact: boolean; conversationId?: string }) {
  const user = useCurrentUser();
  const openIn = useOpenInWorkspace();
  const drawer = useAiDrawer();
  const line = summary(step);
  // a handoff needs the id of the stored step
  const stored = !!step.id && !step.is_error;
  const canSave = stored && step.name === SIMULATION_TOOL && !!user?.permissions.includes("changes.write");
  const canDraft = stored && !compact && step.name === SERVICE_TOOL;
  // the conversation opens in the other chat: the drawer from the compact
  // variant, the change simulation from the drawer
  const simulation = !!conversationId && !step.is_error && step.name === SIMULATION_TOOL;
  const toDrawer = simulation && compact && drawer?.ready ? drawer : null;
  const toChangeSim = simulation && !compact ? openIn : null;
  return (
    <div
      className={"agentpanel-step result-card" + (compact ? " compact" : "")}
      id={step.id ? stepElementId(step.id) : undefined}
      tabIndex={step.id ? -1 : undefined}
    >
      <div className="result-card-head">
        {step.step && <span className="agentpanel-steplabel">{step.step}</span>}
        <span className={"agentpanel-stepname" + (step.is_error ? " bad" : "")}>{step.name}</span>
      </div>
      {line && <p className="result-card-summary">{line}</p>}
      {(canSave || canDraft || toDrawer || toChangeSim) && (
        <div className="result-card-actions">
          {canSave && <SaveSimulation stepId={step.id!} conversationId={conversationId} />}
          {canDraft && <InvestigateEvidence stepId={step.id!} />}
          {toDrawer && (
            <button type="button" className="linkish" onClick={() => toDrawer.openConversation(conversationId!)}>
              Open in drawer
            </button>
          )}
          {toChangeSim && (
            <button
              type="button"
              className="linkish"
              onClick={() => toChangeSim((workspace) => workspace.openChangeSim(conversationId))}
            >
              Open in Change simulation
            </button>
          )}
        </div>
      )}
      {line || compact ? (
        <details className="result-card-raw">
          <summary>Arguments and result</summary>
          <Raw step={step} />
        </details>
      ) : (
        <Raw step={step} />
      )}
    </div>
  );
}

/** The steps of one turn as result cards, behind one disclosure. */
export function ResultCards({
  steps,
  open = false,
  compact = false,
  conversationId,
}: {
  steps: CardStep[];
  open?: boolean;
  /** The variant under the change-simulation chat: every step's arguments
   *  and result sit behind the second disclosure, and the cards carry no
   *  assessment draft action. */
  compact?: boolean;
  /** The conversation the steps belong to, once stored. */
  conversationId?: string;
}) {
  return (
    <details className="agentpanel-steps" open={open}>
      <summary>
        {steps.length} tool call{steps.length === 1 ? "" : "s"}
      </summary>
      {steps.map((step, i) => (
        <ResultCard key={step.id ?? i} step={step} compact={compact} conversationId={conversationId} />
      ))}
    </details>
  );
}
