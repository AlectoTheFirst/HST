/**
 * The evidence pane of the HST AI drawer (shell/AgentDrawer.tsx): the
 * evidence of what the reader picked in the chat, beside it in a wide drawer
 * and behind the Evidence tab in a narrow one.
 *
 * A pick names an answer and, inside it, a statement, a tool step, a record
 * of a step's result or an object (ai/chain.ts). The pane shows:
 * - the evidence chain of the statement, or of the whole answer: a picture
 *   (ai/ChainGraph.tsx, loaded lazily), which "enlarge" shows again in a
 *   dialog at the size of the window, and the same chain as a list of
 *   buttons, each of which opens its node here;
 * - the evidence of the step (ai/evidence.tsx): what it looked up, the
 *   records that support the statement, the objects it read, and Details;
 *   with the steps it builds on and the steps that build on it;
 * - for an object, what it is, the steps that name it and, for a stored or
 *   graph object, a button that opens it in the focused pane;
 * - the result cards of the answer's tool calls (ai/ResultCards.tsx), from
 *   which a simulation is saved and an assessment draft opened. They are
 *   collapsed unless the steps line of a finished answer opened them.
 * While a turn runs, the pane draws the chain of its steps so far, which
 * grows by each step the stream sends; a step node opens the step's evidence.
 * The running turn and its answer share one chain picture.
 */

import { Suspense, lazy, useCallback, useEffect, useMemo, useRef, useState, type ReactNode, type Ref } from "react";
import { createPortal } from "react-dom";
import type { AnswerEnvelope } from "../api/types";
import { DeviceText } from "../shell/deviceNames";
import { useDialogFocus } from "../shell/useDialogFocus";
import { useOpenInWorkspace } from "../workspace/WorkspaceContext";
import { claimSteps, evidenceChain, type ChainEdge, type ChainNode, type ChainObject } from "./chain";
import { statementText } from "./citations";
import { EvidenceView } from "./evidence";
import { ResultCards, type CardStep } from "./ResultCards";
import type { StepsTarget } from "./Transcript";
import type { ConversationChat, ConversationTurn } from "./useConversation";

const ChainGraph = lazy(() => import("./ChainGraph"));

/** What the pane shows: an answer (a turn index, or the running turn) and,
 *  inside it, at most one statement, step, record and object. */
export interface EvidenceSelection {
  turn: StepsTarget;
  claim?: string;
  step?: string;
  /** A record of `step`'s result, null for its summary. */
  pointer?: string | null;
  object?: string;
  /** Opened from the steps line: the tool calls are expanded. */
  steps?: boolean;
}

/** The selection a conversation shows when none is stored, or none fits it:
 *  the running turn, else the newest answer with evidence. */
export function defaultSelection(
  chat: Pick<ConversationChat, "turns" | "isPending" | "runningSteps">,
): EvidenceSelection | undefined {
  if (chat.isPending && chat.runningSteps.length > 0) return { turn: "running" };
  for (let i = chat.turns.length - 1; i >= 0; i--) {
    const turn = chat.turns[i];
    if (turn.role === "assistant" && (turn.envelope || (turn.steps?.length ?? 0) > 0)) return { turn: i };
  }
  return undefined;
}

/** Whether `selection` names an answer of `turns`. */
export function fits(selection: EvidenceSelection, chat: Pick<ConversationChat, "turns" | "isPending">): boolean {
  if (selection.turn === "running") return chat.isPending;
  return chat.turns[selection.turn]?.role === "assistant";
}

/** The id of the chain node a selection shows. */
function selectedNode(selection: EvidenceSelection): string | undefined {
  if (selection.object) return `object:${selection.object}`;
  if (selection.step && selection.pointer !== undefined) {
    return `record:${selection.step}:${selection.pointer ?? "summary"}`;
  }
  if (selection.step) return `step:${selection.step}`;
  if (selection.claim) return `statement:${selection.claim}`;
  return undefined;
}

const COLUMNS: [ChainNode["kind"], string][] = [
  ["statement", "Statements"],
  ["step", "Tool steps"],
  ["record", "Supporting records"],
  ["object", "Objects"],
];

/** The evidence chain at the size of the window, over the drawer. It renders
 *  in `document.body`. */
function ChainDialog({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  const card = useRef<HTMLDivElement | null>(null);
  useDialogFocus(card);
  useEffect(() => {
    // Escape closes this dialog in the capture phase.
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      event.stopPropagation();
      onClose();
    };
    document.addEventListener("keydown", onKey, true);
    return () => document.removeEventListener("keydown", onKey, true);
  }, [onClose]);
  return createPortal(
    <div className="modal-scrim">
      <div ref={card} tabIndex={-1} className="modal-card chain-dialog" role="dialog" aria-modal="true" aria-label={title}>
        <div className="modal-head">
          <h2 className="modal-label">{title}</h2>
          <button type="button" className="modal-close" onClick={onClose}>
            Close
          </button>
        </div>
        <div className="modal-body">
          {children}
        </div>
      </div>
    </div>,
    document.body,
  );
}

function ChainSection({
  nodes,
  edges,
  whole,
  selected,
  onOpen,
}: {
  nodes: ChainNode[];
  edges: ChainEdge[];
  whole: boolean;
  selected?: string;
  onOpen: (node: ChainNode) => void;
}) {
  const chain = useMemo(() => ({ nodes, edges }), [nodes, edges]);
  const builds = edges.filter((edge) => edge.kind === "builds-on");
  const labelOf = new Map(nodes.map((node) => [node.id, node.label]));
  const [large, setLarge] = useState(false);
  const closeLarge = useCallback(() => setLarge(false), []);
  const title = whole ? "Answer evidence chain" : "Statement evidence chain";
  return (
    <section className="chain" aria-label="Evidence chain">
      <div className="chain-head">
        <h3 className="evidence-pane-sub">{title}</h3>
        <button
          type="button"
          className="linkish chain-enlarge"
          aria-haspopup="dialog"
          aria-label="Enlarge evidence chain"
          onClick={() => setLarge(true)}
        >
          Enlarge
        </button>
      </div>
      <Suspense fallback={<div className="chain-graph" aria-hidden="true" />}>
        <ChainGraph chain={chain} selected={selected} onOpen={onOpen} />
      </Suspense>
      {large && (
        <ChainDialog title={title} onClose={closeLarge}>
          <Suspense fallback={<div className="chain-graph large" aria-hidden="true" />}>
            <ChainGraph chain={chain} selected={selected} onOpen={onOpen} large />
          </Suspense>
        </ChainDialog>
      )}
      <details className="chain-text">
        <summary>Chain list</summary>
        {COLUMNS.map(([kind, title]) => {
          const column = nodes.filter((node) => node.kind === kind);
          if (column.length === 0) return null;
          return (
            <div key={kind} role="group" aria-label={title} className="chain-column">
              <span className="evidence-caption">{title}</span>
              <ul>
                {column.map((node) => (
                  <li key={node.id}>
                    <button
                      type="button"
                      className={"linkish chain-node" + (node.id === selected ? " selected" : "")}
                      aria-pressed={node.id === selected}
                      onClick={() => onOpen(node)}
                    >
                      <DeviceText text={node.label} />
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          );
        })}
        {builds.length > 0 && (
          <ul className="chain-builds" aria-label="Builds on">
            {builds.map((edge) => (
              <li key={edge.id}>
                {labelOf.get(edge.target)} takes {edge.value} from {labelOf.get(edge.source)}
              </li>
            ))}
          </ul>
        )}
      </details>
    </section>
  );
}

/** The steps a step builds on, and the steps that build on it, as buttons
 *  that open those steps. */
function BuildsOn({
  label,
  edges,
  onStep,
}: {
  label: string;
  edges: ChainEdge[];
  onStep: (label: string) => void;
}) {
  const id = `step:${label}`;
  const from = edges.filter((edge) => edge.kind === "builds-on" && edge.target === id);
  const to = edges.filter((edge) => edge.kind === "builds-on" && edge.source === id);
  if (from.length === 0 && to.length === 0) return null;
  const stepButton = (node: string) => {
    const other = node.slice("step:".length);
    return (
      <button type="button" className="linkish" onClick={() => onStep(other)} aria-label={`Show step ${other}`}>
        {other}
      </button>
    );
  };
  return (
    <ul className="evidence-builds">
      {from.map((edge) => (
        <li key={edge.id}>
          Takes <DeviceText text={edge.value ?? ""} /> from {stepButton(edge.source)}
        </li>
      ))}
      {to.map((edge) => (
        <li key={edge.id}>
          {stepButton(edge.target)} takes <DeviceText text={edge.value ?? ""} /> from this step
        </li>
      ))}
    </ul>
  );
}

function ObjectDetail({
  object,
  edges,
  onStep,
}: {
  object: ChainObject;
  edges: ChainEdge[];
  onStep: (label: string) => void;
}) {
  const openIn = useOpenInWorkspace();
  const id = `object:${object.key}`;
  const from = edges.filter((edge) => edge.target === id).map((edge) => edge.source);
  const steps = [...new Set(from.map((source) => source.split(":")[1]))];
  return (
    <section className="evidence" aria-label={`Object ${object.label}`}>
      <div className="evidence-head">
        <span className="evidence-lookup">
          <DeviceText text={object.label} />
        </span>
      </div>
      <p className="evidence-caption">
        {object.run ? "Run" : object.uid ? "Graph object" : "Stored object"}
      </p>
      <p className="evidence-caption">
        From{" "}
        {steps.map((label, i) => (
          <span key={label}>
            {i > 0 && ", "}
            <button type="button" className="linkish" onClick={() => onStep(label)} aria-label={`Show step ${label}`}>
              {label}
            </button>
          </span>
        ))}
      </p>
      {openIn && (object.link || object.uid) && (
        <button
          type="button"
          className="context-chip answer-link"
          onClick={() =>
            openIn((workspace) =>
              object.link ? object.link.open(workspace) : workspace.openSearch(undefined, object.uid!),
            )
          }
        >
          {object.uid ? "Open in Explore" : "Open"}
        </button>
      )}
    </section>
  );
}

function AnswerEvidence({
  turn,
  turnIndex,
  question,
  steps,
  envelope,
  selection,
  conversationId,
  onSelect,
}: {
  turn: ConversationTurn;
  turnIndex: StepsTarget;
  question?: string;
  steps: CardStep[];
  envelope?: AnswerEnvelope;
  selection: EvidenceSelection;
  conversationId?: string;
  onSelect: (selection: EvidenceSelection) => void;
}) {
  const turnSteps = useMemo(() => (turn.steps ?? []) as CardStep[], [turn.steps]);
  // a running turn has no envelope yet; its chain holds its steps so far
  const running = turnIndex === "running";
  const built = useMemo(
    () =>
      envelope || running
        ? evidenceChain({
            content: turn.content,
            envelope,
            steps,
            turnSteps: turnSteps.map((step) => step.step).filter((label): label is string => !!label),
            claim: selection.claim,
          })
        : undefined,
    [envelope, running, turn.content, steps, turnSteps, selection.claim],
  );
  const claim = envelope?.claims.find((item) => item.id === selection.claim);
  const known = useMemo(() => {
    const labels = new Set<string>();
    for (const step of steps) if (step.step) labels.add(step.step);
    for (const link of envelope?.links ?? []) if (link.kind === "step" && link.step) labels.add(link.step);
    for (const used of envelope?.tools_used ?? []) labels.add(used.step);
    return labels;
  }, [steps, envelope]);
  const claimLabels = claim ? claimSteps(claim, known) : [];
  // a statement shows the evidence of its first step until another is picked
  const label = selection.step ?? (selection.object ? undefined : claimLabels[0]);
  const step = label ? steps.find((item) => item.step === label) : undefined;
  const stepId =
    step?.id ??
    envelope?.links?.find((link) => link.kind === "step" && link.step === label)?.ref_id ??
    envelope?.tools_used.find((used) => used.step === label)?.step_id;
  const object = selection.object ? built?.objects.get(selection.object) : undefined;
  const edges = built?.chain.edges ?? [];
  const select = (next: Omit<EvidenceSelection, "turn">) => onSelect({ turn: turnIndex, ...next });
  const openNode = (node: ChainNode) => {
    const target = node.target;
    if ("claim" in target) select({ claim: target.claim });
    else if ("object" in target) select({ claim: selection.claim, object: target.object });
    else select({ claim: selection.claim, step: target.step, ...(target.pointer !== undefined && { pointer: target.pointer }) });
  };
  const onStep = (other: string) => select({ claim: selection.claim, step: other });
  const picked = selection.claim !== undefined || selection.step !== undefined || selection.object !== undefined;

  return (
    <>
      {question && (
        <p className="evidence-caption">
          Question: <DeviceText text={question} />
        </p>
      )}
      {picked && (
        <button type="button" className="linkish" onClick={() => onSelect({ turn: turnIndex })}>
          Show whole answer
        </button>
      )}
      {claim && (
        <blockquote className="evidence-statement">
          <DeviceText text={statementText(turn.content, claim)} />
        </blockquote>
      )}
      {claim && claimLabels.length === 0 && (
        <p className="evidence-caption">No tool source</p>
      )}
      {claimLabels.length > 1 && (
        <div className="answer-links" role="group" aria-label="Statement steps">
          {claimLabels.map((other) => (
            <button
              key={other}
              type="button"
              className={"citation-chip" + (other === label ? " open" : "")}
              aria-pressed={other === label}
              onClick={() => onStep(other)}
            >
              {other}
            </button>
          ))}
        </div>
      )}
      {built && built.chain.nodes.length > 0 && (
        <ChainSection
          nodes={built.chain.nodes}
          edges={edges}
          whole={selection.claim === undefined}
          selected={selectedNode({ ...selection, step: label })}
          onOpen={openNode}
        />
      )}
      {object ? (
        <ObjectDetail object={object} edges={edges} onStep={onStep} />
      ) : (
        label &&
        (envelope || running) &&
        stepId && (
          <>
            <EvidenceView
              label={label}
              stepId={stepId}
              claim={claim}
              step={step}
              envelope={envelope}
              onClose={() => select(selection.claim ? { claim: selection.claim } : {})}
            />
            <BuildsOn label={label} edges={edges} onStep={onStep} />
          </>
        )
      )}
      {turnSteps.length > 0 && (
        <ResultCards
          key={`${turnIndex}:${selection.steps ? "open" : "closed"}`}
          steps={turnSteps}
          conversationId={conversationId}
          open={selection.steps === true && !picked}
        />
      )}
    </>
  );
}

export function EvidencePane({
  chat,
  conversationId,
  selection,
  onSelect,
  headingRef,
}: {
  chat: Pick<ConversationChat, "turns" | "runningSteps" | "isPending" | "isLoading">;
  conversationId?: string;
  /** The stored selection of the conversation; the default when absent. */
  selection?: EvidenceSelection;
  onSelect: (selection: EvidenceSelection) => void;
  headingRef?: Ref<HTMLHeadingElement>;
}) {
  const shown = selection && fits(selection, chat) ? selection : defaultSelection(chat);
  // a chip may cite a step of an earlier turn
  const steps = useMemo(() => chat.turns.flatMap((turn) => (turn.steps ?? []) as CardStep[]), [chat.turns]);
  const runningTurn = useMemo<ConversationTurn>(
    () => ({ role: "assistant", content: "", steps: chat.runningSteps }),
    [chat.runningSteps],
  );
  const runningAll = useMemo(() => [...steps, ...chat.runningSteps], [steps, chat.runningSteps]);
  const isRunning = shown?.turn === "running";
  const turn = isRunning ? runningTurn : typeof shown?.turn === "number" ? chat.turns[shown.turn] : undefined;
  const question =
    typeof shown?.turn === "number"
      ? chat.turns
          .slice(0, shown.turn)
          .reverse()
          .find((item) => item.role === "user")?.content
      : undefined;
  return (
    <div className="evidence-pane">
      <h2 className="evidence-pane-title" tabIndex={-1} ref={headingRef}>
        Evidence
      </h2>
      {!shown || chat.isLoading ? (
        <p className="hint">No selection</p>
      ) : (
        turn && (
          <AnswerEvidence
            turn={turn}
            turnIndex={shown.turn}
            question={question}
            steps={isRunning ? runningAll : steps}
            envelope={turn.envelope}
            selection={shown}
            conversationId={conversationId}
            onSelect={onSelect}
          />
        )
      )}
    </div>
  );
}
