/** The chat strip sits at the foot of the change-simulation workspace. */

import { useState, type FormEvent } from "react";
import { Transcript } from "../ai/Transcript";
import type { ChangeSimChat } from "./useChangeSimChat";
import "./changesim.css";

export function ChatPanel({ chat, conversationId }: { chat: ChangeSimChat; conversationId?: string }) {
  const [text, setText] = useState("");

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!text.trim() || chat.isPending || chat.isLoading) return;
    chat.send(text);
    setText("");
  }

  return (
    <div className="chgsim-chat">
      <div className="chgsim-chatlog">
        <Transcript chat={chat} conversationId={conversationId} compact />
      </div>

      <form className="chgsim-field agentpanel-field" onSubmit={handleSubmit}>
        <input
          value={text}
          onChange={(e) => setText(e.target.value)}
          aria-label="Planned change"
          placeholder="Planned change"
          disabled={chat.isPending || chat.isLoading}
        />
        <button type="submit" className="agentpanel-send" disabled={chat.isPending || chat.isLoading}>
          {chat.isPending ? "Asking" : "Send"}
        </button>
        {(chat.turns.length > 0 || chat.isPending) && (
          <button type="button" className="linkish" onClick={chat.reset}>
            New chat
          </button>
        )}
      </form>
    </div>
  );
}
