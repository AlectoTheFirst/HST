import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { EvidenceValue, record } from "./AnalysisResult";
import { IntentEditor } from "./IntentEditor";
import { Field } from "./RequirementComposer";
import type { Assessment, Definition, Intent } from "./types";

export interface Proposal {
  id: string;
  revision: number;
  title: string;
  definition: Record<string, unknown>;
}

function ProposalRevision({
  proposal,
  canOperate,
  assessment,
  onRefresh,
  onEvaluate,
}: {
  proposal: Proposal;
  canOperate: boolean;
  assessment: Assessment;
  onRefresh: () => void;
  onEvaluate: (definition: Definition, protectedRequirements: unknown[]) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [title, setTitle] = useState(proposal.title);
  const [intents, setIntents] = useState(proposal.definition.intents as Intent[]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const history = useQuery({
    queryKey: ["change-revisions", proposal.id, proposal.revision],
    queryFn: () =>
      api<{ revisions: Proposal[] }>(
        `/change-revisions/${encodeURIComponent(proposal.id)}/revisions`,
      ),
  });
  async function save() {
    setBusy(true);
    setError("");
    try {
      await api(`/change-revisions/${encodeURIComponent(proposal.id)}`, {
        method: "PATCH",
        body: {
          title,
          intents,
          preconditions: proposal.definition.preconditions ?? [],
          expected_revision: proposal.revision,
        },
      });
      setEditing(false);
      onRefresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  const source = record(proposal.definition.requirements) as unknown as Definition;
  return (
    <section>
      <h4>
        {proposal.title} / revision {proposal.revision}
      </h4>
      <p>
        {proposal.definition.verification_state === "verified" ? "Verified" : "Needs evaluation"}
      </p>
      <p>
        Original run {String(proposal.definition.source_run_id)}, assessment revision{" "}
        {String(proposal.definition.source_assessment_revision)}
      </p>
      <details>
        <summary>Verified source and exact proposal</summary>
        <EvidenceValue value={proposal.definition} />
      </details>
      {editing ? (
        <fieldset disabled={busy}>
          <legend>Edit proposal revision</legend>
          <Field label="Proposal title" value={title} onChange={setTitle} />
          <IntentEditor value={intents} onChange={setIntents} />
          <button type="button" disabled={!title.trim()} onClick={save}>
            Save proposal revision
          </button>
          <button type="button" onClick={() => setEditing(false)}>
            Cancel proposal editing
          </button>
        </fieldset>
      ) : (
        canOperate && (
          <div className="assessment-actions">
            <button type="button" onClick={() => setEditing(true)}>
              Edit proposal {proposal.id}
            </button>
            <button
              type="button"
              onClick={() =>
                onEvaluate(
                  {
                    ...(source.request || source.requirement ? source : assessment.definition),
                    intents: proposal.definition.intents as Intent[],
                    change_id: proposal.id,
                    change_revision: proposal.revision,
                  },
                  Array.isArray(proposal.definition.protected) ? proposal.definition.protected : [],
                )
              }
            >
              Evaluate proposal revision
            </button>
          </div>
        )
      )}
      <details>
        <summary>Proposal revisions</summary>
        {history.isLoading && <p role="status">Loading proposal history</p>}
        {history.isError && <p role="alert">Could not load proposal history</p>}
        {history.data?.revisions.map((revision) => (
          <details key={revision.revision}>
            <summary>
              Revision {revision.revision}: {String(revision.definition.verification_state)}
            </summary>
            <EvidenceValue value={revision} />
          </details>
        ))}
      </details>
      {error && <p role="alert">{error}</p>}
    </section>
  );
}

export function ProposalPanel({
  proposals,
  ...props
}: {
  proposals: Proposal[];
  canOperate: boolean;
  assessment: Assessment;
  onRefresh: () => void;
  onEvaluate: (definition: Definition, protectedRequirements: unknown[]) => void;
}) {
  return proposals.length ? (
    <section>
      <h3>Saved repair proposals</h3>
      {proposals.map((proposal) => (
        <ProposalRevision
          key={`${proposal.id}:${proposal.revision}`}
          proposal={proposal}
          {...props}
        />
      ))}
    </section>
  ) : null;
}
