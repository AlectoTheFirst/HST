/** The link chips under an answer open the stored objects in `envelope.links`. */

import { DeviceText } from "../shell/deviceNames";
import { useMemo } from "react";
import type { AnswerEnvelope, AnswerLink } from "../api/types";
import { useOpenInWorkspace, type WorkspaceApi } from "../workspace/WorkspaceContext";

export interface LinkChip {
  key: string;
  label: string;
  open: (workspace: WorkspaceApi) => void;
}

/** The chips of an answer's links, each object once, in link order. */
export function linkChips(links: AnswerLink[]): LinkChip[] {
  const assessmentOf = new Map<string, string>();
  const runOf = new Map<string, string>();
  for (const link of links) {
    if (link.step && link.kind === "assessment") assessmentOf.set(link.step, link.ref_id);
    if (link.step && link.kind === "assessment_run") runOf.set(link.step, link.ref_id);
  }
  const chips = new Map<string, LinkChip>();
  const add = (chip: LinkChip) => {
    if (!chips.has(chip.key)) chips.set(chip.key, chip);
  };
  for (const link of links) {
    const id = link.ref_id;
    const revision = link.ref_revision ? ` revision ${link.ref_revision}` : "";
    const assessment = link.step ? assessmentOf.get(link.step) : undefined;
    const run = link.step ? runOf.get(link.step) : undefined;
    if (link.kind === "analysis_session") {
      add({ key: `analysis_session:${id}`, label: `Analysis session ${id}${revision}`, open: (ws) => ws.openAnalysis(id) });
    } else if (link.kind === "assessment") {
      add({ key: `assessment:${id}`, label: `Assessment ${id}`, open: (ws) => ws.openAssessments(id) });
    } else if (link.kind === "assessment_run" && assessment) {
      add({ key: `assessment_run:${id}`, label: `Assessment run ${id}`, open: (ws) => ws.openAssessments(assessment, id) });
    } else if (link.kind === "finding" && assessment && run) {
      add({ key: `finding:${run}:${id}`, label: `Finding ${id}`, open: (ws) => ws.openAssessments(assessment, run) });
    } else if (link.kind === "application") {
      add({ key: `application:${id}`, label: `Application ${id}${revision}`, open: (ws) => ws.openApplications(id) });
    } else if (link.kind === "graph_node") {
      add({ key: `graph_node:${id}`, label: `Object ${id}`, open: (ws) => ws.openSearch(undefined, id) });
    }
  }
  return [...chips.values()];
}

export function AnswerLinks({ envelope }: { envelope: AnswerEnvelope }) {
  const openIn = useOpenInWorkspace();
  const chips = useMemo(() => linkChips(envelope.links ?? []), [envelope]);
  if (!openIn || chips.length === 0) return null;
  return (
    <div className="answer-links" role="group" aria-label="Objects this answer read">
      {chips.map((chip) => (
        <button key={chip.key} type="button" className="context-chip answer-link" onClick={() => openIn(chip.open)}>
          <DeviceText text={chip.label} />
        </button>
      ))}
    </div>
  );
}
