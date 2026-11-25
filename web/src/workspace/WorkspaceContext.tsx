/**
 * The layout persists in localStorage.
 */

import { createContext, useCallback, useContext, useEffect, useMemo, useReducer, useRef } from "react";
import { useLocation, useNavigate } from "react-router";
import { useCurrentUser } from "../auth";
import { readJson, writeJson } from "../shell/storage";
import { withoutUserHistory } from "../userStorage";
import { initial, panes, reduce, repairIds, type Action, type Workspace } from "./layout";
import { isPaneView, RETIRED_VIEWS } from "./views";
import type { AssessmentDraft } from "../assessments/types";

const LAYOUT_KEY = "hst-workspace";

/** The route that renders the workspace (App.tsx). */
export const WORKSPACE_ROUTE = "/";

export interface WorkspaceApi {
  state: Workspace;
  dispatch: (action: Action) => void;
  /** Load a catalog query into the focused pane, switching it to Explore.
   *  `params` prefills the query's declared parameters (command palette). */
  openQuery: (queryKey?: string, cypher?: boolean, params?: Record<string, string>) => void;
  /** Switch the focused pane to Explore's Search tab with the text typed in,
   *  and open one object there when `uid` is given (command palette). */
  openSearch: (text?: string, uid?: string) => void;
  /** Switch the focused pane to a plain view (trace, explore) with no query. */
  openView: (view: "hst" | "trace" | "explore") => void;
  /** Switch the focused pane to the network map. */
  openMap: (scope?: string) => void;
  openSdwan: () => void;
  /** Switch the focused pane to the Equinix Fabric of one metro. */
  openEquinix: () => void;
  /** Switch the focused pane to the snapshot diff ("What changed") view. */
  openDiff: () => void;
  /** Switch the focused pane to the change-simulation workspace, on
   *  `conversationId` when given and on the pane's own conversation otherwise. */
  openChangeSim: (conversationId?: string) => void;
  openAssessments: (assessmentId?: string, runId?: string, draft?: AssessmentDraft) => void;
  openApplications: (applicationId?: string) => void;
  /** Switch the focused pane to Business Applications with a generated draft. */
  openApplicationDraft: (generationId: string) => void;
  openAnalysis: (sessionId?: string, mode?: "connection" | "simulation") => void;
}

const ANALYSIS_SECTIONS = ["results", "scope", "history", "verification"] as const;

const Ctx = createContext<WorkspaceApi | null>(null);

/** USER_HISTORY_KEYS of userStorage.ts lists the 2 keys. */
interface WorkspaceHistoryState {
  hstWorkspace?: Workspace;
  /** The username of the user that wrote `hstWorkspace`. */
  hstWorkspaceUser?: string;
}

function locationFor(workspace: Workspace): string {
  const params = new URLSearchParams(window.location.search);
  for (const key of ["application", "analysis", "analysis_session", "analysis_run", "analysis_section", "assessment", "assessment_run"]) params.delete(key);
  const focused = panes(workspace.root).find((pane) => pane.id === workspace.focus);
  if (focused?.view === "applications" && focused.applicationId) params.set("application", focused.applicationId);
  // The URL holds ?analysis=<session>&analysis_run=<run>&analysis_section=<section>.
  if (focused?.view === "analysis" && focused.analysisSessionId) {
    params.set("analysis", focused.analysisSessionId);
    if (focused.analysisRunId) params.set("analysis_run", focused.analysisRunId);
    if (focused.analysisSection && focused.analysisSection !== "results") params.set("analysis_section", focused.analysisSection);
  }
  if (focused?.view === "analysis" && focused.assessmentId) {
    params.set("assessment", focused.assessmentId);
    if (focused.assessmentRunId) params.set("assessment_run", focused.assessmentRunId);
  }
  const query = params.toString();
  return `${window.location.pathname}${query ? `?${query}` : ""}${window.location.hash}`;
}

/** URL params the rest of the shell owns: the conversation of the open
 *  HST AI drawer (ai/drawer.tsx). The workspace keeps them in the URL, and a
 *  change to one of them adds no history entry. */
const SHELL_PARAMS = ["ai"];

function workspacePart(location: string): string {
  // the location is a path; the base only makes it parseable
  const url = new URL(location, "http://workspace.invalid");
  for (const key of SHELL_PARAMS) url.searchParams.delete(key);
  return `${url.pathname}${url.search}${url.hash}`;
}

function restoreLayout(): Workspace {
  const saved = readJson<Workspace | null>(LAYOUT_KEY, null);
  if (saved?.root && typeof saved.focus === "string") {
    try {
      // the id counter starts at 0 on every load
      const { node: repaired } = repairIds(saved.root);
      const translate = (node: typeof repaired): typeof repaired => {
        if (node.type === "split") return { ...node, a: translate(node.a), b: translate(node.b) };
        if (node.view === "changesim") return { ...node, view: "analysis", analysisMode: "simulation" };
        if (node.view === "assessments") return { ...node, view: "analysis", analysisMode: "connection" };
        return node;
      };
      const root = translate(repaired);
      const restored = panes(root);
      // a pane of a retired view opens the view that replaced it, and keeps
      // its place among the others
      for (const p of restored) {
        const next = RETIRED_VIEWS[p.view as string];
        if (next) {
          p.view = next;
          delete p.mapScope;
        }
      }
      const ids = restored.every((p) => isPaneView(p.view))
        ? restored.map((p) => p.id)
        : [];
      if (ids.length > 0) {
        return { root, focus: ids.includes(saved.focus) ? saved.focus : ids[0] };
      }
    } catch {
      // fall through to a fresh workspace
    }
  }
  return initial();
}

function restore(): Workspace {
  const workspace = restoreLayout();
  const params = new URLSearchParams(window.location.search);
  const applicationId = params.get("application");
  if (applicationId) return reduce(workspace, { type: "open-application", id: workspace.focus, applicationId });
  const sessionId = params.get("analysis") ?? params.get("analysis_session");
  const section = params.get("analysis_section");
  if (sessionId) return reduce(workspace, {
    type: "open-analysis", id: workspace.focus, sessionId,
    section: ANALYSIS_SECTIONS.find((item) => item === section),
    runId: params.get("analysis_run") ?? undefined,
  });
  const assessmentId = params.get("assessment");
  return assessmentId ? {
    ...reduce(workspace, { type: "open-analysis", id: workspace.focus, mode: "connection" }),
    root: (() => {
      const opened = reduce(workspace, { type: "open-analysis", id: workspace.focus, mode: "connection" });
      const attach = (node: typeof opened.root): typeof opened.root => node.type === "split"
        ? { ...node, a: attach(node.a), b: attach(node.b) }
        : node.id === opened.focus ? { ...node, assessmentId, assessmentRunId: params.get("assessment_run") ?? undefined } : node;
      return attach(opened.root);
    })(),
  } : workspace;
}

export function WorkspaceProvider({ children }: { children: React.ReactNode }) {
  const [state, dispatch] = useReducer(reduce, undefined, restore);
  const username = useCurrentUser()?.username ?? null;
  const historyLocation = useRef(locationFor(state));
  const restoringHistory = useRef(false);
  /** The layout of the last write to the history. */
  const historyLayout = useRef<Workspace | null>(null);

  useEffect(() => {
    writeJson(LAYOUT_KEY, { ...state, schemaVersion: 2 });
  }, [state]);

  // The history state holds the layout only while a user is signed in.
  useEffect(() => {
    const rest = withoutUserHistory(window.history.state);
    const historyState: WorkspaceHistoryState =
      username === null ? rest : { ...rest, hstWorkspace: state, hstWorkspaceUser: username };
    if (historyLayout.current === state) {
      // A change of the user alone keeps the URL of the entry.
      window.history.replaceState(historyState, "");
      return;
    }
    historyLayout.current = state;
    const location = locationFor(state);
    if (restoringHistory.current) {
      restoringHistory.current = false;
      window.history.replaceState(historyState, "", location);
    } else if (workspacePart(location) !== workspacePart(historyLocation.current)) {
      window.history.pushState(historyState, "", location);
    } else {
      window.history.replaceState(historyState, "", location);
    }
    historyLocation.current = location;
  }, [state, username]);

  // A history entry restores the layout only for the user that wrote the entry.
  useEffect(() => {
    function onPopState(event: PopStateEvent) {
      const entry = event.state as WorkspaceHistoryState | null;
      if (username === null || entry?.hstWorkspaceUser !== username) return;
      const restored = entry.hstWorkspace;
      if (!restored?.root || typeof restored.focus !== "string") return;
      restoringHistory.current = true;
      historyLocation.current = locationFor(restored);
      dispatch({ type: "restore", state: restored });
    }
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, [username]);

  const openQuery = useCallback(
    (queryKey?: string, cypher?: boolean, params?: Record<string, string>) =>
      dispatch({ type: "open-query", id: state.focus, queryKey, cypher, params }),
    [state.focus],
  );

  const openSearch = useCallback(
    (text?: string, uid?: string) => dispatch({ type: "open-search", id: state.focus, text, uid }),
    [state.focus],
  );

  const openView = useCallback(
    (view: "hst" | "trace" | "explore") => dispatch({ type: "view", id: state.focus, view }),
    [state.focus],
  );

  const openMap = useCallback(
    (scope?: string) => dispatch({ type: "open-map", id: state.focus, scope }),
    [state.focus],
  );
  // one SD-WAN edge, its WAN links and tunnels, and the hubs they end on
  const openSdwan = useCallback(
    () => dispatch({ type: "view", id: state.focus, view: "sdwan" }),
    [state.focus],
  );
  // the Fabric ports of one metro, the switches they land on, and their circuits
  const openEquinix = useCallback(
    () => dispatch({ type: "view", id: state.focus, view: "equinix" }),
    [state.focus],
  );

  const openDiff = useCallback(
    () => dispatch({ type: "view", id: state.focus, view: "diff" }),
    [state.focus],
  );

  const openChangeSim = useCallback(
    (conversationId?: string) => dispatch({ type: "open-changesim", id: state.focus, conversationId }),
    [state.focus],
  );

  const openAssessments = useCallback(
    (assessmentId?: string, runId?: string, draft?: AssessmentDraft) => dispatch({ type: "open-assessment", id: state.focus, assessmentId, runId, draft }),
    [state.focus],
  );
  const openApplications = useCallback(
    (applicationId?: string) => dispatch({ type: "open-application", id: state.focus, applicationId }),
    [state.focus],
  );
  const openApplicationDraft = useCallback(
    (generationId: string) => dispatch({ type: "set-application-draft", id: state.focus, draft: { generationId } }),
    [state.focus],
  );
  const openAnalysis = useCallback(
    (sessionId?: string, mode?: "connection" | "simulation") => dispatch({ type: "open-analysis", id: state.focus, sessionId, mode }),
    [state.focus],
  );

  const value = useMemo(
    () => ({ state, dispatch, openQuery, openSearch, openView, openMap, openSdwan, openEquinix, openDiff, openChangeSim, openAssessments, openApplications, openApplicationDraft, openAnalysis }),
    [state, openQuery, openSearch, openView, openMap, openSdwan, openEquinix, openDiff, openChangeSim, openAssessments, openApplications, openApplicationDraft, openAnalysis],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

/** Null outside a provider. */
export function useWorkspace(): WorkspaceApi | null {
  return useContext(Ctx);
}

/** Runs one workspace action. */
export type OpenInWorkspace = (action: (workspace: WorkspaceApi) => void) => void;

/**
 * Runs a workspace action from any route. Off the workspace route it first
 * navigates there, so the focused pane the action changes is on screen. Null
 * outside a provider.
 */
export function useOpenInWorkspace(): OpenInWorkspace | null {
  const workspace = useWorkspace();
  const { pathname } = useLocation();
  const navigate = useNavigate();
  return useMemo<OpenInWorkspace | null>(
    () =>
      workspace
        ? (action) => {
            if (pathname !== WORKSPACE_ROUTE) navigate(WORKSPACE_ROUTE);
            action(workspace);
          }
        : null,
    [workspace, pathname, navigate],
  );
}
