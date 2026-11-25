/**
 * The conversations of the signed-in user in the HST AI drawer
 * (shell/AgentDrawer.tsx), newest first (GET /api/ai/conversations). The list
 * titles a conversation without a title by its first question. Each entry
 * names its last change and the run its newest answer read, or the run it is
 * pinned to; a conversation of another surface names that surface.
 *
 * The search field filters the loaded list by title. A click on an entry
 * shows that conversation in the drawer. Delete asks for confirmation first,
 * then deletes the conversation with its messages and steps
 * (DELETE /api/ai/conversations/{id}); deleting the conversation on screen
 * starts a new chat.
 */

import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../api/client";
import type { AiConversation } from "../api/types";
import { DeviceText } from "../shell/deviceNames";

/** The query key of the list; the drawer refreshes it after a turn. */
export const CONVERSATIONS_KEY = ["ai", "conversations"] as const;
/** The most conversations the list loads. */
export const LIST_LIMIT = 100;

const SURFACES: Record<string, string> = {
  changesim: "Change simulation",
  assessment_qa: "Assessment",
};

const UNTITLED = "Untitled conversation";

function when(value: string | null): string {
  if (!value) return "";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "" : date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function titleOf(conversation: AiConversation): string {
  return conversation.title.trim() || UNTITLED;
}

/** The query of the list, shared by the list and the drawer's breadcrumb. */
export function conversationsQuery(enabled: boolean) {
  return {
    queryKey: CONVERSATIONS_KEY,
    queryFn: () => api<{ conversations: AiConversation[] }>(`/ai/conversations?limit=${LIST_LIMIT}`),
    enabled,
  };
}

function runOf(conversation: AiConversation): string | undefined {
  if (conversation.pin) return `Pinned to run ${conversation.pin}`;
  return conversation.last_run ? `Run ${conversation.last_run}` : undefined;
}

export function ConversationList({
  enabled,
  current,
  onSelect,
  onDeleted,
}: {
  /** Load the list; false while the drawer is closed. */
  enabled: boolean;
  /** The conversation on screen. */
  current?: string;
  onSelect: (id: string) => void;
  /** The conversation on screen was deleted. */
  onDeleted: () => void;
}) {
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const [confirming, setConfirming] = useState<string | null>(null);
  const searchField = useRef<HTMLInputElement | null>(null);
  const deleteButtons = useRef(new Map<string, HTMLButtonElement>());
  // where the focus goes when the confirmation closes: back to the delete
  // button after Cancel, to the search field after a delete
  const refocus = useRef<string | "search" | null>(null);
  useEffect(() => {
    const target = refocus.current;
    if (target === null || confirming !== null) return;
    refocus.current = null;
    if (target === "search") searchField.current?.focus();
    else deleteButtons.current.get(target)?.focus();
  });
  const list = useQuery(conversationsQuery(enabled));
  const remove = useMutation({
    mutationFn: (id: string) => api<void>(`/ai/conversations/${encodeURIComponent(id)}`, { method: "DELETE" }),
    onSuccess: (_, id) => {
      refocus.current = "search";
      setConfirming(null);
      if (id === current) onDeleted();
      queryClient.setQueryData<{ conversations: AiConversation[] }>(CONVERSATIONS_KEY, (prev) =>
        prev ? { conversations: prev.conversations.filter((item) => item.id !== id) } : prev,
      );
      void queryClient.invalidateQueries({ queryKey: CONVERSATIONS_KEY });
    },
  });

  const needle = search.trim().toLowerCase();
  const conversations = (list.data?.conversations ?? []).filter(
    (item) => !needle || titleOf(item).toLowerCase().includes(needle),
  );

  return (
    <div className="ai-convos">
      <input
        ref={searchField}
        type="search"
        className="ai-convos-search"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        aria-label="Search conversations"
        placeholder="Search conversations"
      />
      {list.isPending && enabled && <p className="hint">Loading conversations</p>}
      {list.isError && (
        <p className="hint" role="alert">
          Conversations not loaded{list.error instanceof ApiError ? `: ${list.error.message}` : ""}
        </p>
      )}
      {remove.isError && (
        <p className="hint" role="alert">
          Conversation not deleted{remove.error instanceof ApiError ? `: ${remove.error.message}` : ""}
        </p>
      )}
      {list.isSuccess && conversations.length === 0 && (
        <p className="hint">{needle ? "No matching conversation" : "No conversations"}</p>
      )}
      <ul className="ai-convos-list" aria-label="Conversations">
        {conversations.map((item) => {
          const title = titleOf(item);
          const run = runOf(item);
          const surface = SURFACES[item.surface];
          return (
            <li key={item.id} className={"ai-convo" + (item.id === current ? " current" : "")}>
              <button
                type="button"
                className="ai-convo-open"
                aria-current={item.id === current ? "true" : undefined}
                onClick={() => onSelect(item.id)}
              >
                <span className="ai-convo-title">
                  <DeviceText text={title} />
                </span>
                <span className="ai-convo-meta">
                  {when(item.last_message_at)}
                  {surface && <span className="ai-convo-badge">{surface}</span>}
                  {run && <span className="ai-convo-badge">{run}</span>}
                </span>
              </button>
              {confirming === item.id ? (
                <span className="ai-convo-confirm" role="group" aria-label={`Confirm delete ${title}`}>
                  <span>Delete conversation</span>
                  <button
                    type="button"
                    className="linkish"
                    disabled={remove.isPending}
                    onClick={() => remove.mutate(item.id)}
                  >
                    Delete
                  </button>
                  <button
                    type="button"
                    className="linkish"
                    onClick={() => {
                      refocus.current = item.id;
                      setConfirming(null);
                    }}
                  >
                    Cancel
                  </button>
                </span>
              ) : (
                <button
                  ref={(element) => {
                    if (element) deleteButtons.current.set(item.id, element);
                    else deleteButtons.current.delete(item.id);
                  }}
                  type="button"
                  className="linkish ai-convo-delete"
                  aria-label={`Delete ${title}`}
                  onClick={() => {
                    remove.reset();
                    setConfirming(item.id);
                  }}
                >
                  Delete
                </button>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
