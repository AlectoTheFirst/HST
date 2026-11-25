/**
 * The turns of one agent conversation, as the HST AI
 * drawer (shell/AgentDrawer.tsx) and the change-simulation chat
 * (changesim/ChatPanel.tsx) both show them: the user's turns as text, the
 * answers as markdown with citation chips, the tool calls as result cards,
 * and the notes for a load, a running turn and an error.
 *
 * With `onSteps`, as in the drawer, the tool calls of an answer and of the
 * running turn are one line that counts them and opens them in the evidence
 * pane (ai/EvidencePane.tsx), and `evidence` ties the citation chips of each
 * answer to that pane.
 */

import { useMemo, type ReactNode } from "react";
import { AnswerText, type AnswerEvidence } from "./citations";
import { ResultCards, type CardStep } from "./ResultCards";
import type { ConversationChat, ConversationTurn } from "./useConversation";

/** The answer a steps line opens: a turn's index, or the running turn. */
export type StepsTarget = number | "running";

function stepCount(n: number): string {
  return `${n} step${n === 1 ? "" : "s"}`;
}

export function Transcript({
  chat,
  conversationId,
  compact = false,
  extras,
  onSteps,
  evidence,
}: {
  chat: Pick<ConversationChat, "turns" | "runningSteps" | "isPending" | "isLoading" | "error">;
  conversationId?: string;
  /** The compact result cards of an inline chat. */
  compact?: boolean;
  /** More content under an answer, before its result cards. */
  extras?: (turn: ConversationTurn) => ReactNode;
  /** Show the tool calls as a line that opens them elsewhere. */
  onSteps?: (target: StepsTarget) => void;
  /** The evidence pane's side of the answer at index `turn`. */
  evidence?: (turn: number) => AnswerEvidence;
}) {
  // a chip may cite a step of an earlier turn
  const steps = useMemo(() => chat.turns.flatMap((turn) => (turn.steps ?? []) as CardStep[]), [chat.turns]);
  return (
    <>
      {chat.turns.map((turn, i) =>
        turn.role === "user" ? (
          <div className="chat-turn user" key={i}>
            <p>{turn.content}</p>
          </div>
        ) : (
          <div className="chat-turn assistant" key={i}>
            {/* the agent answers in markdown; rendered as React elements
                (shell/markdown.tsx), never as HTML strings */}
            <div
              className={
                "chat-md" +
                (turn.declined ? " agentpanel-declined" : "") +
                (turn.failed ? " agentpanel-failed" : "")
              }
            >
              <AnswerText content={turn.content} envelope={turn.envelope} steps={steps} evidence={evidence?.(i)} />
            </div>
            {extras?.(turn)}
            {turn.steps && turn.steps.length > 0 &&
              (onSteps ? (
                <button type="button" className="linkish chat-steps" onClick={() => onSteps(i)}>
                  {stepCount(turn.steps.length)}
                </button>
              ) : (
                <ResultCards steps={turn.steps} conversationId={conversationId} compact={compact || undefined} />
              ))}
          </div>
        ),
      )}
      {chat.isLoading && <span className="agentpanel-note">Loading conversation</span>}
      {chat.isPending && <span className="agentpanel-note">Working</span>}
      {chat.isPending &&
        chat.runningSteps.length > 0 &&
        (onSteps ? (
          <button type="button" className="linkish chat-steps" onClick={() => onSteps("running")}>
            {stepCount(chat.runningSteps.length)} so far
          </button>
        ) : (
          <ResultCards
            steps={chat.runningSteps}
            conversationId={compact ? undefined : conversationId}
            open
            compact={compact || undefined}
          />
        ))}
      {chat.error && <span className="agentpanel-note">{chat.error}</span>}
    </>
  );
}
