/**
 * "Draft Business Application" under an answer in the HST AI drawer.
 *
 * The action starts a generation (POST /api/ai/service-drafts) from the user
 * messages of the conversation up to the answer, at the run the answer was
 * pinned to, and opens the draft in the Business Applications workspace of the
 * focused pane. The request names the conversation and the message ids; the
 * server reads the text from the stored messages. The pane keeps the
 * generation id across a reload. The action shows only on the workspace
 * route.
 */

import { useState } from "react";
import { useLocation } from "react-router";
import { api } from "../api/client";
import type { AiConversation, AnswerEnvelope, ConversationMessage } from "../api/types";
import { useWorkspace, WORKSPACE_ROUTE } from "../workspace/WorkspaceContext";

/** The generator's bounds on its source messages and on the description they
 *  join into (src/hst/app/routes/application_generator.py). */
export const MAX_DRAFT_MESSAGES = 20;
export const MAX_DRAFT_CHARS = 4000;

/** The ids of the user messages that describe the application: the newest
 *  user messages before the answer `answerId`, in conversation order, as many
 *  as the generator takes. The server joins them with a blank line. */
export function draftSourceMessages(messages: ConversationMessage[], answerId: string): string[] {
  const ordered = [...messages].sort((a, b) => a.seq - b.seq);
  const answer = ordered.findIndex((message) => message.id === answerId);
  const questions = (answer === -1 ? ordered : ordered.slice(0, answer)).filter((message) => message.role === "user" && message.content.trim() !== "");
  const chosen: string[] = [];
  let chars = 0;
  for (let index = questions.length - 1; index >= 0 && chosen.length < MAX_DRAFT_MESSAGES; index--) {
    const size = questions[index].content.trim().length + (chosen.length > 0 ? 2 : 0);
    if (chars + size > MAX_DRAFT_CHARS) break;
    chosen.unshift(questions[index].id);
    chars += size;
  }
  return chosen;
}

export function DraftApplication({ envelope }: { envelope: AnswerEnvelope }) {
  const workspace = useWorkspace();
  const { pathname } = useLocation();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [started, setStarted] = useState("");
  const run = envelope.snapshot.id;
  if (!workspace || pathname !== WORKSPACE_ROUTE || envelope.kind !== "answer" || !run || !/^\d+$/.test(run)) return null;

  async function draft(snapshot: string) {
    setBusy(true);
    setError("");
    try {
      const conversation = await api<AiConversation>(`/ai/conversations/${encodeURIComponent(envelope.conversation_id)}`);
      const messageIds = draftSourceMessages(conversation.messages ?? [], envelope.message_id);
      if (messageIds.length === 0) throw new Error(`No question within ${MAX_DRAFT_CHARS} characters`);
      const { generation_id } = await api<{ generation_id: string }>("/ai/service-drafts", {
        method: "POST",
        body: { conversation_id: envelope.conversation_id, message_ids: messageIds, snapshot },
      });
      setStarted(generation_id);
      workspace?.openApplicationDraft(generation_id);
    } catch (cause) {
      setError(cause instanceof Error && cause.message ? cause.message : "Draft not started");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="result-card-actions">
      {started ? (
        <>
          <span className="result-card-note" role="status">
            Draft started at run {run}
          </span>
          <button type="button" className="linkish" onClick={() => workspace.openApplicationDraft(started)}>
            Open draft
          </button>
        </>
      ) : (
        <button type="button" className="linkish" disabled={busy} onClick={() => void draft(run)}>
          {busy ? "Starting draft" : "Draft Business Application"}
        </button>
      )}
      {error && (
        <span className="result-card-note bad" role="alert">
          {error}
        </span>
      )}
    </div>
  );
}
