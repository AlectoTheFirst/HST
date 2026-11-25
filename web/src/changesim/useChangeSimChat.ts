/** The change-simulation chat is a server-held conversation on the `changesim` surface. */

import { useCallback } from "react";
import { useAiPageContext } from "../ai/context";
import { useConversation, type ConversationChat } from "../ai/useConversation";

export interface ChangeSimChat extends Omit<ConversationChat, "send"> {
  send: (question: string) => void;
}

export function useChangeSimChat(
  conversationId?: string,
  onConversation?: (id: string | undefined) => void,
): ChangeSimChat {
  const pageContext = useAiPageContext();
  const chat = useConversation({
    surface: "changesim",
    conversationId,
    onConversation,
    includeContext: true,
  });
  const { send: sendQuestion } = chat;
  const send = useCallback(
    (question: string) => sendQuestion(question, pageContext ?? undefined),
    [sendQuestion, pageContext],
  );
  return { ...chat, send };
}
