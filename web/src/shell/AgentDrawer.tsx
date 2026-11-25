/**
 * The HST AI chat drawer.
 *
 * The conversation is held on the server (ai/useConversation.ts). Its id is
 * drawer state (ai/drawer.tsx), kept in localStorage and, while the drawer is
 * open, in the URL, so a reload shows the same transcript; "New chat"
 * cancels a running turn and starts a new conversation. The tool steps of an
 * answer render as result cards (ai/ResultCards.tsx), from which a change
 * simulation is saved as an analysis session or opened in the change
 * simulation, and a service evaluation opens its assessment draft. While a
 * turn runs, the drawer shows the cards of the steps recorded so far. Under an
 * answer, link chips open the stored objects its steps read (ai/links.tsx).
 *
 * Every ask also carries the page context (ai/context.tsx): the route, the
 * focused pane and what its pages registered. The chips above the input show
 * each part. A removed chip's part is left out of the next asks.
 *
 * An answer with an answer envelope shows its step markers as citation chips
 * (ai/citations.tsx). Inside the workspace, an answer pinned to a run offers
 * "Draft Business Application", which generates a definition from the
 * questions before it (ai/DraftApplication.tsx).
 *
 * The drawer has three parts: the user's conversations (ai/ConversationList.tsx),
 * the chat, and the evidence pane (ai/EvidencePane.tsx). The chat holds the
 * answers with their citation chips and, per answer, one line that counts its
 * tool steps; the steps themselves, the evidence of a chip or a statement and
 * the evidence chain show in the evidence pane. The pane keeps its selection
 * per conversation, in localStorage. A drawer at least WIDE_WIDTH wide shows
 * the three parts side by side. A narrower one shows one level at a time:
 * the conversations, the chat, and the evidence of that chat. A breadcrumb
 * (Chats / the chat's title / Evidence) names the level on screen, and each
 * level above it is a button back to it. The evidence opens only from a pick
 * in the chat.
 */

import { DeviceText } from "./deviceNames";
import { useCallback, useEffect, useId, useMemo, useRef, useState, type FormEvent } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { contextChips, routeLabel, useAiPageContext, withoutChips } from "../ai/context";
import { ConversationList, CONVERSATIONS_KEY, conversationsQuery } from "../ai/ConversationList";
import { DraftApplication } from "../ai/DraftApplication";
import { EvidencePane, type EvidenceSelection } from "../ai/EvidencePane";
import { AnswerLinks } from "../ai/links";
import { Transcript } from "../ai/Transcript";
import { useConversation } from "../ai/useConversation";
import { ResizeHandle } from "./ResizeHandle";
import { readJson, writeJson } from "./storage";

export { ASK_MAX_ATTEMPTS, ASK_POLL_MS } from "../ai/useConversation";

/** Drawer width: user-resizable via the left-edge handle, persisted. */
const WIDTH_KEY = "hst.agent.width";
const DEFAULT_WIDTH = 520;
const MIN_WIDTH = 380;
/** Pixels one arrow key moves the drawer edge. */
const KEY_STEP = 24;
/** From this width on, the conversations, the chat and the evidence pane sit
 *  side by side. */
export const WIDE_WIDTH = 960;
/** The share of the window the drawer may take (theme.css: max-width). */
const MAX_SHARE = 0.9;
/** The evidence pane's selection per conversation. */
export const EVIDENCE_KEY = "hst.agent.evidence";
/** Conversations whose selection is kept. */
const KEPT_SELECTIONS = 50;

/** The level a narrow drawer shows: the conversations, one chat, or the
 *  evidence of that chat. */
type View = "chats" | "chat" | "evidence";
/** The title of a chat that has none yet. */
const NEW_CHAT = "New chat";

function storedSelections(): Record<string, EvidenceSelection> {
  const stored = readJson<unknown>(EVIDENCE_KEY, {});
  return typeof stored === "object" && stored !== null && !Array.isArray(stored)
    ? (stored as Record<string, EvidenceSelection>)
    : {};
}

export function AgentDrawer({
  open,
  onClose,
  conversationId,
  onConversation,
}: {
  open: boolean;
  onClose: () => void;
  /** The conversation to show; absent until the first question creates one. */
  conversationId?: string;
  /** Receives the id of a conversation the drawer created, and undefined
   *  after New chat. */
  onConversation: (id: string | undefined) => void;
}) {
  const [text, setText] = useState("");
  const [width, setWidth] = useState(() => readJson(WIDTH_KEY, DEFAULT_WIDTH));
  // the width "narrow" goes back to
  const narrowWidth = useRef(DEFAULT_WIDTH);
  const [viewport, setViewport] = useState(() => window.innerWidth);
  const [view, setView] = useState<View>("chat");
  const [selections, setSelections] = useState(storedSelections);
  const log = useRef<HTMLDivElement | null>(null);
  const evidenceHeading = useRef<HTMLHeadingElement | null>(null);
  const focusEvidence = useRef(false);
  // the breadcrumb of the level on screen, focused after a breadcrumb button
  const currentCrumb = useRef<HTMLSpanElement | null>(null);
  const focusCrumb = useRef(false);
  const crumbsId = useId();
  const queryClient = useQueryClient();
  const pageContext = useAiPageContext();
  // keys of the chips the user removed; a chip is attached by default
  const [removed, setRemoved] = useState<ReadonlySet<string>>(() => new Set());
  const chips = useMemo(
    () => (pageContext ? contextChips(pageContext).filter((chip) => !removed.has(chip.key)) : []),
    [pageContext, removed],
  );
  const chat = useConversation({ surface: "drawer", conversationId, onConversation });
  const { turns } = chat;
  const conversations = useQuery(conversationsQuery(open));
  const listed = conversations.data?.conversations.find((item) => item.id === conversationId);
  // the stored title, else the first question, else the chat is new
  const title =
    listed?.title.trim() || turns.find((turn) => turn.role === "user")?.content.trim() || NEW_CHAT;

  const maxWidth = Math.floor(viewport * MAX_SHARE);
  const wide = Math.min(width, maxWidth) >= WIDE_WIDTH;
  const canExpand = maxWidth >= WIDE_WIDTH;

  useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  useEffect(() => {
    const onResize = () => setViewport(window.innerWidth);
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  // jsdom has no scrollTo.
  useEffect(() => {
    const el = log.current;
    if (el?.scrollTo) el.scrollTo(0, el.scrollHeight);
  }, [turns, chat.isPending, chat.runningSteps]);

  // a new conversation, a finished turn or a reopened drawer changes the list
  useEffect(() => {
    if (open) void queryClient.invalidateQueries({ queryKey: CONVERSATIONS_KEY });
  }, [open, conversationId, turns.length, queryClient]);

  // a pick in the chat moves the focus to the evidence it opened
  useEffect(() => {
    if (!focusEvidence.current || view !== "evidence") return;
    focusEvidence.current = false;
    evidenceHeading.current?.focus();
  }, [view, selections]);

  // a breadcrumb button is gone once pressed; the focus goes to the level it opened
  useEffect(() => {
    if (!focusCrumb.current) return;
    focusCrumb.current = false;
    currentCrumb.current?.focus();
  }, [view]);

  const selectionKey = conversationId ?? "";
  const selection = selections[selectionKey];
  /** Show `next` in the evidence pane. A pick in the chat also moves a
   *  narrow drawer to the Evidence tab, with the focus on its heading; a pick
   *  inside the pane leaves the focus where it is. */
  const select = useCallback(
    (next: EvidenceSelection, fromChat = false) => {
      setSelections((prev) => {
        const all = { ...prev, [selectionKey]: next };
        // the selection of a chat not stored yet is not kept
        const kept = Object.entries(all)
          .filter(([key]) => key !== "")
          .slice(-KEPT_SELECTIONS);
        writeJson(EVIDENCE_KEY, Object.fromEntries(kept));
        return all;
      });
      if (fromChat && !wide) {
        focusEvidence.current = true;
        setView("evidence");
      }
    },
    [selectionKey, wide],
  );
  const selectInPane = useCallback((next: EvidenceSelection) => select(next), [select]);

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const question = text.trim();
    if (!question || chat.isPending || chat.isLoading) return;
    setText("");
    chat.send(question, pageContext ? withoutChips(pageContext, removed) : undefined);
  }

  function resetChat() {
    // cancels a running turn; its answer never lands here
    chat.reset();
    setRemoved(new Set());
    setSelections(({ "": _unsaved, ...stored }) => stored);
  }

  function newChat() {
    resetChat();
    setView("chat");
  }

  /** Go back up to `level` from the breadcrumb. */
  function backTo(level: View) {
    focusCrumb.current = true;
    setView(level);
  }

  function toggleWidth() {
    let next: number;
    if (wide) {
      next = Math.min(narrowWidth.current, WIDE_WIDTH - 1);
    } else {
      narrowWidth.current = width;
      next = maxWidth;
    }
    setWidth(next);
    writeJson(WIDTH_KEY, next);
  }

  /** The attributes of one of the three parts: a region, side by side in a
   *  wide drawer and hidden in a narrow one unless it is the level on screen. */
  const part = (key: View, label: string) => ({
    role: "region",
    "aria-label": label,
    hidden: !wide && view !== key,
  });

  /** One level of the breadcrumb: the level on screen as text, a level above
   *  it as a button back. */
  const crumb = (level: View, label: string) => (
    <li className="drawer-crumb">
      {view === level ? (
        <span ref={currentCrumb} tabIndex={-1} aria-current="location" title={label}>
          <DeviceText text={label} />
        </span>
      ) : (
        <button type="button" className="linkish" title={label} onClick={() => backTo(level)}>
          <DeviceText text={label} />
        </button>
      )}
    </li>
  );

  return (
    <aside
      className={"drawer" + (open ? " open" : "") + (wide ? " wide" : "")}
      style={{ width }}
      aria-label="HST AI"
      aria-hidden={!open}
      inert={!open}
    >
      <ResizeHandle
        orientation="vertical"
        ariaLabel="Resize HST AI"
        className="drawer-resize"
        onDrag={(pos) => setWidth(Math.max(MIN_WIDTH, window.innerWidth - pos.clientX))}
        onCommit={() => writeJson(WIDTH_KEY, width)}
        // the handle on the left edge: a step to the left widens the drawer
        onKeyAdjust={(step) => {
          const next = Math.max(MIN_WIDTH, width - step * KEY_STEP);
          setWidth(next);
          writeJson(WIDTH_KEY, next);
        }}
      />
      <div className="drawer-head">
        <span className="eyebrow">HST AI</span>
        <span className="drawer-headactions">
          {(turns.length > 0 || chat.isPending) && (
            <button type="button" className="linkish" onClick={newChat}>
              New chat
            </button>
          )}
          {canExpand && (
            <button
              type="button"
              className="linkish"
              onClick={toggleWidth}
              aria-label={wide ? "Narrow HST AI" : "Expand HST AI"}
            >
              {wide ? "Narrow" : "Expand"}
            </button>
          )}
          <button type="button" className="linkish" onClick={onClose} aria-label="Close HST AI">
            Close
          </button>
        </span>
      </div>

      {!wide && (
        <nav className="drawer-crumbs" aria-labelledby={crumbsId}>
          <span id={crumbsId} className="sr-only">
            Breadcrumb
          </span>
          <ol>
            {crumb("chats", "Chats")}
            {view !== "chats" && crumb("chat", title)}
            {view === "evidence" && crumb("evidence", "Evidence")}
          </ol>
        </nav>
      )}

      <div className="drawer-parts">
        <section className="drawer-part drawer-chats" {...part("chats", "Conversations")}>
          <ConversationList
            enabled={open}
            current={conversationId}
            onSelect={(id) => {
              if (id !== conversationId) {
                setRemoved(new Set());
                onConversation(id);
              }
              setView("chat");
            }}
            // the list stays in view; the next question starts a new chat
            onDeleted={resetChat}
          />
        </section>

        <section className="drawer-part drawer-chat" {...part("chat", "Chat")}>
          <div className="drawer-body" ref={log}>
            <Transcript
              chat={chat}
              conversationId={conversationId}
              onSteps={(target) =>
                select(target === "running" ? { turn: target } : { turn: target, steps: true }, true)
              }
              evidence={(turn) => ({
                selected: selection?.turn === turn ? { claim: selection.claim, step: selection.step } : undefined,
                onSelect: (pick) => select({ turn, ...pick }, true),
              })}
              extras={(turn) =>
                turn.envelope && (
                  <>
                    <AnswerLinks envelope={turn.envelope} />
                    {!turn.failed && !turn.declined && <DraftApplication envelope={turn.envelope} />}
                  </>
                )
              }
            />
          </div>

          {pageContext && (
            <div className="drawer-context" role="group" aria-label="Context">
              <span className="context-chip">{routeLabel(pageContext.route)}</span>
              {chips.map((chip) => (
                <span className="context-chip" key={chip.key}>
                  <DeviceText text={chip.label} />
                  <button
                    type="button"
                    className="context-chip-remove"
                    aria-label={`Remove ${chip.label}`}
                    onClick={() => setRemoved((prev) => new Set(prev).add(chip.key))}
                  >
                    Remove
                  </button>
                </span>
              ))}
            </div>
          )}

          <form className="drawer-foot agentpanel-field" onSubmit={handleSubmit}>
            <input
              value={text}
              onChange={(e) => setText(e.target.value)}
              aria-label="Ask HST AI"
              placeholder="Question"
              disabled={chat.isPending || chat.isLoading}
            />
            <button type="submit" className="agentpanel-send" disabled={chat.isPending || chat.isLoading}>
              {chat.isPending ? "Asking" : "Send"}
            </button>
          </form>
        </section>

        <section className="drawer-part drawer-evidence" {...part("evidence", "Evidence")}>
          <EvidencePane
            chat={chat}
            conversationId={conversationId}
            selection={selection}
            onSelect={selectInPane}
            headingRef={evidenceHeading}
          />
        </section>
      </div>
    </aside>
  );
}
