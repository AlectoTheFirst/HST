/** The provider holds the state of the HST AI drawer (shell/AgentDrawer.tsx). */

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useLocation } from "react-router";
import { api } from "../api/client";
import type { AiConversation, ConversationSurface, PageContext } from "../api/types";
import { useCurrentUser } from "../auth";
import { readJson, writeJson } from "../shell/storage";
import { useHealth } from "../shell/useHealth";
import { useWorkspace } from "../workspace/WorkspaceContext";
import { objectContext, useAiPaneId, type AiContextFragment } from "./context";

/** The URL param that names the conversation the open drawer shows. */
export const AI_PARAM = "ai";
/** The id of the drawer's conversation in localStorage. */
export const CONVERSATION_KEY = "hst.agent.conversation";
const CONVERSATION_ID = /^[A-Za-z0-9-]{1,64}$/;

export interface AiDrawerApi {
  open: boolean;
  /** The drawer's conversation; undefined until the next question creates one. */
  conversationId?: string;
  /** The top bar offers the drawer, so the agent can answer. */
  ready: boolean;
  setOpen: (open: boolean) => void;
  setConversation: (id: string | undefined) => void;
  /** Open the drawer on a stored conversation. */
  openConversation: (id: string) => void;
  /** Create a conversation on `surface` with `context`, open the drawer on
   *  it and return its id. */
  startConversation: (surface: ConversationSurface, context: PageContext) => Promise<string>;
}

const Ctx = createContext<AiDrawerApi | null>(null);

function urlConversation(): string | undefined {
  const id = new URLSearchParams(window.location.search).get(AI_PARAM);
  return id && CONVERSATION_ID.test(id) ? id : undefined;
}

function storedConversation(): string | undefined {
  const id = readJson<unknown>(CONVERSATION_KEY, null);
  return typeof id === "string" && id ? id : undefined;
}

/** Set the `ai` param of the current URL to `id`, or remove it. */
function writeParam(id: string | undefined): void {
  const params = new URLSearchParams(window.location.search);
  if ((params.get(AI_PARAM) ?? undefined) === id) return;
  if (id === undefined) params.delete(AI_PARAM);
  else params.set(AI_PARAM, id);
  const query = params.toString();
  window.history.replaceState(
    window.history.state,
    "",
    `${window.location.pathname}${query ? `?${query}` : ""}${window.location.hash}`,
  );
}

export function AiDrawerProvider({ inUrl = false, children }: { inUrl?: boolean; children: ReactNode }) {
  const [fromUrl] = useState(() => (inUrl ? urlConversation() : undefined));
  const [open, setOpen] = useState(fromUrl !== undefined);
  const [conversationId, setConversationId] = useState(() => fromUrl ?? storedConversation());
  const signedIn = useCurrentUser() !== null;
  const ready = useHealth(signedIn).data?.agent === true && signedIn;
  const { pathname, search } = useLocation();
  const shown = open && ready ? conversationId : undefined;

  useEffect(() => {
    if (!inUrl) return;
    writeParam(shown);
    const restore = () => writeParam(shown);
    window.addEventListener("popstate", restore);
    return () => window.removeEventListener("popstate", restore);
  }, [inUrl, shown, pathname, search]);
  useEffect(() => {
    if (!inUrl) return;
    return () => writeParam(undefined);
  }, [inUrl]);
  // the top bar opens the conversation last shown, also after the param is gone
  useEffect(() => {
    if (fromUrl !== undefined) writeJson(CONVERSATION_KEY, fromUrl);
  }, [fromUrl]);

  const setConversation = useCallback((id: string | undefined) => {
    setConversationId(id);
    writeJson(CONVERSATION_KEY, id ?? null);
  }, []);
  const openConversation = useCallback(
    (id: string) => {
      setConversation(id);
      setOpen(true);
    },
    [setConversation],
  );
  const startConversation = useCallback(
    async (surface: ConversationSurface, context: PageContext) => {
      const created = await api<AiConversation>("/ai/conversations", {
        method: "POST",
        body: { surface, context },
      });
      openConversation(created.id);
      return created.id;
    },
    [openConversation],
  );

  const value = useMemo<AiDrawerApi>(
    () => ({ open, conversationId, ready, setOpen, setConversation, openConversation, startConversation }),
    [open, conversationId, ready, setConversation, openConversation, startConversation],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

/** The drawer state, or null outside an `AiDrawerProvider`. */
export function useAiDrawer(): AiDrawerApi | null {
  return useContext(Ctx);
}

export type OpenConversation = (surface: ConversationSurface, fragment: AiContextFragment) => Promise<string>;

/**
 * Opens a conversation about one object in the drawer, with the object as the
 * conversation's page context. `fragment` names the object; the current path
 * and the calling page's pane complete the context. Undefined while the
 * drawer is not offered.
 */
export function useOpenConversation(): OpenConversation | undefined {
  const drawer = useAiDrawer();
  const paneId = useAiPaneId();
  const workspace = useWorkspace()?.state ?? null;
  return useMemo(
    () =>
      drawer?.ready
        ? (surface, fragment) => drawer.startConversation(surface, objectContext(paneId, workspace, fragment))
        : undefined,
    [drawer, paneId, workspace],
  );
}
