/**
 * Citation chips for the answers of the HST AI drawer and the
 * change-simulation chat.
 *
 * An answer ends each statement with the labels of the tool steps it rests
 * on, such as `[s3]`. With the answer envelope
 * (src/hst/app/ai/envelope.py), the markers render as chips. A statement
 * the server matched to a step, and a nested list item that takes the
 * markers of its parent, get a chip at their end. A chip whose step a
 * statement cites validly opens the evidence of that step below the answer
 * (ai/evidence.tsx), in this answer or an earlier one; the same chip closes
 * it. A chip whose marker a statement cites and that names no step with a
 * result says so. A marker that no statement carries, such as one in a
 * heading or a table header row, renders as a neutral chip.
 *
 * The statements no tool step supports are counted in one line under the
 * answer; opening it lists them and highlights them in the answer. An answer
 * whose steps read more than one run names the runs. An answer without an
 * envelope renders as its markdown alone.
 *
 * With `evidence`, as in the HST AI drawer, a chip and the text of a
 * statement select their evidence for the evidence pane (ai/EvidencePane.tsx),
 * and the selected statement is marked in the answer.
 */

import { useNamer } from "../shell/deviceNames";
import { useState, type ReactNode } from "react";
import type { AnswerClaim, AnswerEnvelope } from "../api/types";
import {
  claimTag,
  HIGHLIGHT_CLOSE,
  HIGHLIGHT_OPEN,
  renderMarkdown,
  RESERVED,
  STATEMENT_CLOSE,
  statementTag,
  type Citations,
} from "../shell/markdown";
import { EvidenceView } from "./evidence";
import type { CardStep } from "./ResultCards";

export { nearestStep, stepElementId } from "./stepElement";

export interface CitationView {
  /** The answer text with claim tags before the markers of each statement,
   *  a chip at the end of each statement that has none in its text, and,
   *  with `highlight`, the unsupported statements between highlight marks. */
  text: string;
  /** The step id of each label a statement cites validly or is matched to. */
  steps: Map<string, string>;
  /** The labels a statement cites that name no step with a result. */
  invalid: Set<string>;
  /** The runs the answer read, when it read more than one. */
  runs: string[];
  /** The statements no tool step supports. */
  unsupported: AnswerClaim[];
}

/** A step marker as src/hst/app/ai/envelope.py reads it. */
const MARKER = /\[s\d{1,9}(?:[ \t]*,[ \t]*s\d{1,9})*\]/g;

/** The code point offsets of the markers in `chars`, outside inline code. */
function markerOffsets(chars: string[]): number[] {
  const text = chars.join("").replace(/`[^`]+`/g, (code) => "x".repeat(code.length));
  return Array.from(text.matchAll(MARKER), (m) => Array.from(text.slice(0, m.index)).length);
}

/** The labels of the chip a statement without a marker in its text gets: the
 *  steps it is matched to, or the markers it takes from its parent item. */
export function endLabels(claim: AnswerClaim): string[] {
  if (claim.citation_status === "matched") return [...new Set((claim.support ?? []).map((item) => item.step))];
  return claim.citations;
}

/** What the chips of one answer need from its envelope. The claim spans
 *  count code points, so the text is split into code points before the tags
 *  are placed. With `statements`, the text of each statement is tagged too. */
export function citationView(
  content: string,
  envelope: AnswerEnvelope,
  highlight = false,
  statements = false,
): CitationView {
  const steps = new Map<string, string>();
  for (const link of envelope.links ?? []) {
    if (link.kind === "step" && link.step) steps.set(link.step, link.ref_id);
  }
  const invalid = new Set(
    envelope.claims.flatMap((claim) => claim.citations).filter((label) => !steps.has(label)),
  );
  const runs = [
    ...new Set(
      [envelope.snapshot.id, ...(envelope.snapshot.others_used ?? [])].filter(
        (run): run is string => typeof run === "string" && run !== "",
      ),
    ),
  ];
  // a private-use character in the answer itself must not read as a tag
  const chars = Array.from(content.replace(RESERVED, "�"));
  const unsupported = envelope.claims.filter((claim) => claim.citation_status === "uncited");
  if (envelope.answer_markdown === content) {
    // [offset, order, text]: inserted from the end, so the offsets hold
    const inserts: [number, number, string][] = [];
    for (const claim of envelope.claims) {
      const [start, end] = claim.span;
      if (end > chars.length) continue;
      const markers = markerOffsets(chars.slice(start, end));
      for (const at of markers) inserts.push([start + at, 0, claimTag(claim.id)]);
      const labels = markers.length === 0 ? endLabels(claim) : [];
      if (labels.length > 0) inserts.push([end, 1, `${claimTag(claim.id)}[${labels.join(", ")}]`]);
      if (highlight && claim.citation_status === "uncited") {
        inserts.push([start, 0, HIGHLIGHT_OPEN], [end, 2, HIGHLIGHT_CLOSE]);
      }
      if (statements) inserts.push([start, -1, statementTag(claim.id)], [end, 3, STATEMENT_CLOSE]);
    }
    inserts.sort((a, b) => b[0] - a[0] || b[1] - a[1]);
    for (const [at, , text] of inserts) chars.splice(at, 0, text);
  }
  return { text: chars.join(""), steps, invalid, runs: runs.length > 1 ? runs : [], unsupported };
}

/** The text of one statement as a reader sees it: no markers or marks. */
export function statementText(content: string, claim: AnswerClaim): string {
  return Array.from(content)
    .slice(claim.span[0], claim.span[1])
    .join("")
    .replace(MARKER, "")
    .replace(/[`*]/g, "")
    .replace(/\s+/g, " ")
    // a marker removed before the full stop leaves a space behind
    .replace(/ ([.,;:!?])/g, "$1")
    .trim();
}

function CitationChip({
  label,
  stepId,
  invalid,
  open,
  onOpen,
}: {
  label: string;
  stepId: string | undefined;
  invalid: boolean;
  open: boolean;
  onOpen: () => void;
}) {
  if (stepId === undefined && invalid) {
    return (
      <span className="citation-chip invalid" title="No step with a result">
        {label}
      </span>
    );
  }
  if (stepId === undefined) {
    return (
      <span className="citation-chip neutral" title="Not in a statement">
        {label}
      </span>
    );
  }
  return (
    <button
      type="button"
      className={"citation-chip" + (open ? " open" : "")}
      aria-label={`Show evidence of ${label}`}
      aria-expanded={open}
      onClick={onOpen}
    >
      {label}
    </button>
  );
}

/** The one line under an answer that counts its unsupported statements, and
 *  lists them when opened. */
function Unsupported({
  content,
  claims,
  onToggle,
}: {
  content: string;
  claims: AnswerClaim[];
  onToggle: (open: boolean) => void;
}) {
  const name = useNamer();
  const n = claims.length;
  return (
    <details className="citation-unsupported" onToggle={(e) => onToggle(e.currentTarget.open)}>
      <summary>
        {n === 1 ? "1 statement without tool source" : `${n} statements without tool source`}
      </summary>
      <ul>
        {claims.map((claim) => (
          <li key={claim.id}>{name(statementText(content, claim))}</li>
        ))}
      </ul>
    </details>
  );
}

/** What a chip or a statement selects for the evidence pane: a statement,
 *  one of its steps, or neither for the whole answer. */
export interface EvidencePick {
  claim?: string;
  step?: string;
}

/** The evidence pane's side of an answer: what it shows, and the call that
 *  selects a chip or a statement. */
export interface AnswerEvidence {
  selected?: EvidencePick;
  onSelect: (pick: EvidencePick) => void;
}

/** The markdown of one answer, with its citations when it has an envelope.
 *  `steps` are the steps of the conversation, which the evidence reads. */
export function AnswerText({
  content,
  envelope,
  steps = [],
  evidence,
}: {
  content: string;
  envelope?: AnswerEnvelope;
  steps?: CardStep[];
  /** Select the evidence for the evidence pane. */
  evidence?: AnswerEvidence;
}): ReactNode {
  const name = useNamer();
  const [highlight, setHighlight] = useState(false);
  const [inline, setInline] = useState<{ label: string; claim?: string } | null>(null);
  if (!envelope) return renderMarkdown(name(content));
  const view = citationView(content, envelope, highlight, evidence !== undefined);
  const open = evidence
    ? evidence.selected?.step !== undefined
      ? { label: evidence.selected.step, claim: evidence.selected.claim }
      : null
    : inline;
  const isOpen = (label: string, claim?: string) => open?.label === label && open.claim === claim;
  const toggle = (label: string, claim?: string) => {
    if (evidence) evidence.onSelect(isOpen(label, claim) ? {} : { claim, step: label });
    else setInline(isOpen(label, claim) ? null : { label, claim });
  };
  const citations: Citations = {
    chip: (label, key, claim) => (
      <CitationChip
        key={key}
        label={label}
        stepId={view.steps.get(label)}
        invalid={view.invalid.has(label)}
        open={isOpen(label, claim)}
        onOpen={() => toggle(label, claim)}
      />
    ),
    highlight: (children, key) => (
      <mark key={key} className="citation-highlight">
        {children}
      </mark>
    ),
    ...(evidence && {
      // the chip is the keyboard's way to a statement's evidence
      statement: (children: ReactNode, key: string, claim: string) => (
        // eslint-disable-next-line jsx-a11y/click-events-have-key-events, jsx-a11y/no-static-element-interactions
        <span
          key={key}
          className={"claim-text" + (evidence.selected?.claim === claim ? " selected" : "")}
          onClick={() => evidence.onSelect({ claim })}
        >
          {children}
        </span>
      ),
    }),
  };
  const openStep = !evidence && open ? view.steps.get(open.label) : undefined;
  return (
    <>
      {view.runs.length > 0 && (
        <p className="citation-runs">Runs: {view.runs.join(", ")}</p>
      )}
      {renderMarkdown(name(view.text), citations)}
      {open && openStep && (
        <EvidenceView
          label={open.label}
          stepId={openStep}
          claim={envelope.claims.find((claim) => claim.id === open.claim)}
          step={steps.find((step) => step.id === openStep)}
          envelope={envelope}
          onClose={() => setInline(null)}
        />
      )}
      {view.unsupported.length > 0 && envelope.answer_markdown === content && (
        <Unsupported content={content} claims={view.unsupported} onToggle={setHighlight} />
      )}
    </>
  );
}
