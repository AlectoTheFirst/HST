import { modeText } from "../results/text";
import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import type { SnapshotList } from "../api/types";
import { api } from "../api/client";
import { AssistantDraftPanel } from "./AssistantDraftPanel";
import { KnownTrafficForm } from "./KnownTrafficForm";
import { emptyServiceClues, serviceClues } from "./guided";
import { AnalysisForm } from "./AnalysisForm";
import { IntentEditor } from "./IntentEditor";
import { PinnedSnapshotPicker } from "./PinnedSnapshotPicker";
import { Field, RequirementComposer } from "./RequirementComposer";
import { ServicePicker } from "./ServicePicker";
import { WorkflowChoices, workflowTitle } from "./WorkflowChoices";
import { conditionSentence, emptyRequirement, requirementError } from "./types";
import type {
  AnalysisKind,
  Assessment,
  AssessmentDraft,
  Definition,
  SavedRequirement,
} from "./types";
import type { ServiceSelection, ServiceClues, TrafficEndpoints } from "./guided";

function message(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}
export function AssessmentEditor({
  initial,
  draft,
  busy,
  onSave,
  onCancel,
}: {
  initial?: Assessment;
  draft?: AssessmentDraft;
  busy: boolean;
  onSave: (title: string, definition: Definition, analysis?: Record<string, unknown>) => void;
  onCancel: () => void;
}) {
  const original = initial?.definition ?? draft?.definition;
  const [title, setTitle] = useState(initial?.title ?? draft?.title ?? "");
  const [definition, setDefinition] = useState<Definition>(
    original ?? {
      request: emptyRequirement(),
      intents: [],
      mode: "possible",
      snapshot: "",
      freshness_s: 86400,
      priority: 1,
    },
  );
  const [kind, setKind] = useState<AnalysisKind>(draft?.kind ?? "troubleshoot");
  const [manual, setManual] = useState(false);
  const [clues, setClues] = useState<ServiceClues>(() =>
    serviceClues(draft?.analysis?.service_clues),
  );
  const [trafficClues, setTrafficClues] = useState<ServiceClues | null>(() =>
    draft?.analysis?.service_clues ? serviceClues(draft.analysis.service_clues) : null,
  );
  const [trafficEndpoints, setTrafficEndpoints] = useState<TrafficEndpoints>({});
  const [review, setReview] = useState(false);
  const [input, setInput] = useState<Record<string, unknown>>(draft?.analysis ?? {});
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [savingRequirement, setSavingRequirement] = useState(false);
  const queryClient = useQueryClient();
  const snapshots = useQuery({
    queryKey: ["snapshots"],
    queryFn: () => api<SnapshotList>("/snapshots"),
  });
  const [snapshotInitialized, setSnapshotInitialized] = useState(!!original?.snapshot);
  if (!snapshotInitialized && snapshots.data?.current) {
    setSnapshotInitialized(true);
    setDefinition({ ...definition, snapshot: String(snapshots.data.current) });
  }
  const named = definition.request && !requirementError(definition.request);
  function selectService(item: ServiceSelection) {
    setDefinition({
      ...definition,
      request: item.request,
      requirement: undefined,
      requirement_id: item.requirementId,
      requirement_revision: item.requirementRevision,
      origin_requirement:
        item.originRequirement ?? (item.origin === "graph" ? item.uid : undefined),
      origin_snapshot:
        item.originSnapshot ?? (item.origin === "graph" ? definition.snapshot : undefined),
    });
    setTitle(item.name);
    setManual(false);
    setTrafficClues(null);
    setError("");
    setInput({
      kind,
      ...(input.before_snapshot ? { before_snapshot: input.before_snapshot } : {}),
    });
  }
  function normalized(): Definition | null {
    if (!definition.snapshot) {
      setError("No snapshot selected");
      return null;
    }
    const invalid = definition.requirement
      ? null
      : requirementError(definition.request ?? emptyRequirement());
    if (invalid) {
      setError(invalid);
      return null;
    }
    if (!title.trim()) {
      setError("No assessment name");
      return null;
    }
    if (
      !Number.isInteger(definition.freshness_s) ||
      definition.freshness_s < 60 ||
      definition.freshness_s > 31536000
    ) {
      setError("Freshness seconds from 60 to 31536000");
      return null;
    }
    if (
      !Number.isInteger(definition.priority ?? 1) ||
      (definition.priority ?? 1) < 1 ||
      (definition.priority ?? 1) > 100
    ) {
      setError("Requirement priority from 1 to 100");
      return null;
    }
    const next = { ...definition };
    if (next.requirement) delete next.request;
    else delete next.requirement;
    return next;
  }
  async function saveRequirement() {
    const next = normalized();
    if (!next) return;
    const reusable = { ...next };
    delete reusable.requirement_id;
    delete reusable.requirement_revision;
    delete reusable.change_id;
    delete reusable.change_revision;
    delete reusable.deployments;
    delete reusable.collection_actions;
    setSavingRequirement(true);
    setError("");
    try {
      const saved = await api<SavedRequirement>("/requirements", {
        method: "POST",
        body: {
          title: next.request?.name || title.trim(),
          definition: { ...reusable, intents: [] },
        },
      });
      setDefinition({
        ...definition,
        request: saved.definition.request,
        requirement: undefined,
        requirement_id: saved.id,
        requirement_revision: saved.revision,
      });
      setNotice(`Service saved as requirement revision ${saved.revision}`);
      void queryClient.invalidateQueries({ queryKey: ["requirements"] });
    } catch (e) {
      setError(message(e));
    } finally {
      setSavingRequirement(false);
    }
  }
  if (review) {
    const assessment: Assessment = {
      id: initial?.id ?? "",
      title,
      definition,
      revision: initial?.revision ?? 1,
      created_at: initial?.created_at ?? "",
      updated_at: initial?.updated_at ?? "",
    };
    return (
      <section>
        <h2>{workflowTitle(kind)}</h2>
        <p>
          {title} at snapshot {definition.snapshot}
        </p>
        <button type="button" disabled={busy} onClick={() => setReview(false)}>
          Change service or question
        </button>
        <AnalysisForm
          key={`${kind}:${definition.snapshot}`}
          assessment={assessment}
          busy={busy}
          initialKind={kind}
          initialInput={input}
          onSubmit={(analysis) => {
            const next = normalized();
            if (next) onSave(title.trim(), next, analysis);
          }}
        />
        {error && <p role="alert">{error}</p>}
      </section>
    );
  }
  return (
    <section className="assessment-guided-editor">
      <fieldset disabled={busy || savingRequirement} aria-label="Assessment definition">
        <h2>{initial ? `Edit revision ${initial.revision}` : "New assessment"}</h2>
        <PinnedSnapshotPicker
          label="Pinned snapshot"
          value={definition.snapshot}
          onChange={(snapshot) => {
            setSnapshotInitialized(true);
            setTrafficEndpoints({});
            setTrafficClues(null);
            const graphService = !!definition.origin_requirement || !!definition.requirement;
            setDefinition({
              ...definition,
              snapshot,
              ...(graphService
                ? {
                    request: emptyRequirement(),
                    requirement: undefined,
                    origin_requirement: undefined,
                    origin_snapshot: undefined,
                  }
                : {}),
            });
            setInput({ kind, snapshot });
            setNotice(graphService ? "Service cleared for the new snapshot" : "Snapshot changed");
          }}
        />
        <ServicePicker
          key={definition.snapshot}
          snapshot={definition.snapshot}
          label="Find a service"
          onSelect={selectService}
          initialClues={clues}
          onCluesChange={setClues}
          onDefineTraffic={(next, endpoints) => {
            setClues(next);
            setTrafficEndpoints(endpoints ?? {});
            setTrafficClues(next);
            setManual(false);
          }}
        />
        <details>
          <summary>Describe the problem</summary>
          <AssistantDraftPanel
            key={`${definition.snapshot}:${JSON.stringify(clues)}`}
            snapshot={definition.snapshot}
            initialQuestion={[clues.application, clues.destination, clues.client, clues.location]
              .filter(Boolean)
              .join("; ")}
            onManual={(next) => {
              const known = Object.values(next).some(Boolean) ? serviceClues(next) : clues;
              setClues(known);
              setTrafficEndpoints({});
              setTrafficClues(known);
              setManual(false);
            }}
            onDraft={(next) => {
              setDefinition(next.definition);
              setTitle(next.title);
              setKind(next.kind ?? "troubleshoot");
              setInput(next.analysis ?? {});
              setManual(false);
              setError("");
              if (next.analysis?.service_clues) {
                const known = serviceClues(next.analysis.service_clues);
                setClues(known);
                setTrafficClues(known);
              } else setTrafficClues(null);
              setNotice("Proposed service and analysis ready for review");
            }}
          />
        </details>
        {trafficClues && (
          <KnownTrafficForm
            key={JSON.stringify([definition.snapshot, trafficClues, trafficEndpoints])}
            clues={trafficClues}
            endpoints={trafficEndpoints}
            onCancel={() => setTrafficClues(null)}
            onApply={(request) => {
              setDefinition({
                ...definition,
                request,
                requirement: undefined,
                requirement_id: undefined,
                requirement_revision: undefined,
                origin_requirement: undefined,
                origin_snapshot: undefined,
              });
              setTitle(request.name);
              setTrafficClues(null);
              setManual(false);
              setInput({ kind });
              setError("");
              setNotice("Traffic definition prepared");
            }}
          />
        )}
        {!trafficClues && (
          <button
            type="button"
            onClick={() => {
              setTrafficEndpoints({});
              setTrafficClues(Object.values(clues).some(Boolean) ? clues : emptyServiceClues());
              setManual(false);
            }}
          >
            Define known traffic
          </button>
        )}
        {named && (
          <section className="assessment-context" aria-label="Selected service">
            <h3>{definition.request!.name}</h3>
            <p>
              {definition.request!.sources.join(", ")} to {definition.request!.destination}
            </p>
            <p>
              {conditionSentence(definition.request!.condition)}, {definition.request!.success}{" "}
              connectivity
            </p>
            <ul>
              {definition.request!.members.map((member) => (
                <li key={member.name}>
                  {member.name}: {member.addresses.join(", ")} /{" "}
                  {member.proto ?? definition.request!.proto ?? "protocol unspecified"} / port{" "}
                  {member.port ?? definition.request!.port ?? "unspecified"}
                </li>
              ))}
            </ul>
          </section>
        )}
        <button type="button" aria-expanded={manual} onClick={() => setManual(!manual)}>
          {manual
            ? "Close service editor"
            : named
              ? "Edit selected service"
              : "Define service manually"}
        </button>
        {manual && (
          <RequirementComposer
            value={definition.request ?? emptyRequirement()}
            onChange={(request) =>
              setDefinition({
                ...definition,
                request,
                requirement: undefined,
                requirement_id: undefined,
                requirement_revision: undefined,
                origin_requirement: undefined,
                origin_snapshot: undefined,
              })
            }
          />
        )}
        <h3>Question</h3>
        <WorkflowChoices
          selected={kind}
          allowVerify={!!initial?.definition.deployments?.length}
          onChoose={(next) => {
            setKind(next);
            setInput({ ...input, kind: next });
          }}
        />
        <Field label="Assessment title" value={title} onChange={setTitle} required />
        <details>
          <summary>Assumptions, freshness and proposed changes</summary>
          <div className="assessment-fields">
            <label className="assessment-field">
              <span>Forwarding mode</span>
              <select
                value={definition.mode}
                onChange={(e) => setDefinition({ ...definition, mode: e.target.value })}
              >
                <option value="possible">{modeText("possible")}</option>
                <option value="guaranteed">{modeText("guaranteed")}</option>
              </select>
            </label>
            <Field
              label="Freshness seconds"
              type="number"
              value={definition.freshness_s}
              onChange={(v) => setDefinition({ ...definition, freshness_s: Number(v) })}
            />
            <Field
              label="Requirement priority"
              type="number"
              value={definition.priority ?? 1}
              onChange={(v) => setDefinition({ ...definition, priority: Number(v) })}
            />
          </div>
          <IntentEditor
            value={definition.intents}
            onChange={(intents) => setDefinition({ ...definition, intents })}
          />
          <button type="button" onClick={saveRequirement}>
            Save requirement
          </button>
        </details>
        {error && <p role="alert">{error}</p>}
        {notice && <p role="status">{notice}</p>}
        <div className="assessment-actions">
          <button
            type="button"
            onClick={() => {
              if (normalized()) {
                setError("");
                setReview(true);
              }
            }}
          >
            Review analysis scope
          </button>
          <button
            type="button"
            onClick={() => {
              const next = normalized();
              if (next) onSave(title.trim(), next);
            }}
          >
            {initial ? "Save new revision" : "Save assessment"}
          </button>
          <button type="button" onClick={onCancel}>
            Cancel editing
          </button>
        </div>
      </fieldset>
    </section>
  );
}
