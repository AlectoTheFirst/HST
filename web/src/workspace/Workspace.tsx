/**
 * The split workspace is a tree of panes, each showing one view.
 *
 * The render is flat: `tile()` turns the pane tree into absolute rectangles and
 * every pane renders as a keyed sibling of every other one.
 */

import { Suspense, lazy, useCallback, useEffect, useRef } from "react";
import HstMapPage from "../hst/HstMapPage";
import TracePage from "../flowdesk/TracePage";
import ExplorePage from "../explore/ExplorePage";
import { ApplicationPageBoundary } from "../applications/ApplicationPageBoundary";

const NetworkMapPage = lazy(() => import("../netmap/NetworkMapPage"));
const DiffPage = lazy(() => import("../diff/DiffPage"));
const ChangeSimPage = lazy(() => import("../changesim/ChangeSimPage"));
const AssessmentsPage = lazy(() => import("../assessments/AssessmentsPage"));
const ApplicationsPage = lazy(() => import("../applications/ApplicationsPage"));
const AnalysisWorkspace = lazy(() => import("../analysis/AnalysisWorkspace"));
const SdwanPage = lazy(() => import("../sdwan/SdwanPage"));
const EquinixPage = lazy(() => import("../equinix/EquinixPage"));


import { ResizeHandle, type DragPos } from "../shell/ResizeHandle";
import { neighbour, tile, type Node, type Pane, type Rect } from "./layout";
import { useWorkspace } from "./WorkspaceContext";
import { VIEW_LABEL } from "./views";
import { AnalysisSections } from "./AnalysisSections";
import { AiPaneScope } from "../ai/context";

/** Percentage slack when deciding whether a pane edge is the workspace edge:
 *  a 1/3 ratio does not land on a round number. */
const EPS = 0.001;
/** Half the visual gap between two panes; each side of a seam contributes one. */
const HALF_GUTTER = 3;

function paneStyle(rect: Rect): React.CSSProperties {
  const l = rect.left > EPS ? HALF_GUTTER : 0;
  const r = rect.left + rect.width < 100 - EPS ? HALF_GUTTER : 0;
  const t = rect.top > EPS ? HALF_GUTTER : 0;
  const b = rect.top + rect.height < 100 - EPS ? HALF_GUTTER : 0;
  return {
    left: `calc(${rect.left}% + ${l}px)`,
    top: `calc(${rect.top}% + ${t}px)`,
    width: `calc(${rect.width}% - ${l + r}px)`,
    height: `calc(${rect.height}% - ${t + b}px)`,
  };
}

export function Workspace() {
  const ws = useWorkspace();
  const frames = useRef(new Map<string, HTMLElement>());

  const move = useCallback(
    (dir: "left" | "right" | "up" | "down") => {
      if (!ws) return;
      const rects = new Map(
        [...frames.current].map(([id, el]) => {
          const r = el.getBoundingClientRect();
          return [id, { x: r.x, y: r.y, w: r.width, h: r.height }] as const;
        }),
      );
      const next = neighbour(rects, ws.state.focus, dir);
      if (next) ws.dispatch({ type: "focus", id: next });
    },
    [ws],
  );

  useEffect(() => {
    if (!ws) return;
    function onKey(e: KeyboardEvent) {
      if (!(e.ctrlKey || e.metaKey) || !e.shiftKey) return;
      const target = e.target instanceof Element ? e.target : null;
      if (target?.closest("input, textarea, select, [contenteditable]")) return;
      const focus = ws!.state.focus;
      const key = e.key.toLowerCase();
      const actions: Record<string, () => void> = {
        "\\": () => ws!.dispatch({ type: "split", id: focus, dir: "row" }),
        // Standard layouts report Shift+\ as "|", the same way Shift+- is "_".
        "|": () => ws!.dispatch({ type: "split", id: focus, dir: "row" }),
        "-": () => ws!.dispatch({ type: "split", id: focus, dir: "col" }),
        _: () => ws!.dispatch({ type: "split", id: focus, dir: "col" }),
        // Ctrl/Cmd+Shift+W is reserved by the browser
        backspace: () => ws!.dispatch({ type: "close", id: focus }),
        arrowleft: () => move("left"),
        arrowright: () => move("right"),
        arrowup: () => move("up"),
        arrowdown: () => move("down"),
      };
      const run = actions[key];
      if (run) {
        e.preventDefault();
        run();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [ws, move]);

  if (!ws) return null;

  const layout = tile(ws.state.root);
  const count = layout.panes.length;

  return (
    <div className="workspace">
      <h1 className="sr-only">Workspace</h1>
      {layout.panes.map(({ pane, rect }) => {
        // two panes of one view get distinct region names: "Trace pane 2"
        const same = layout.panes.filter((p) => p.pane.view === pane.view);
        const ordinal = same.length > 1 ? same.findIndex((p) => p.pane.id === pane.id) + 1 : 0;
        return (
          <PaneFrame key={pane.id} pane={pane} rect={rect} count={count} ordinal={ordinal} frames={frames} />
        );
      })}
      {layout.dividers.map((d) => (
        <Divider key={d.id} id={d.id} dir={d.dir} rect={d.rect} box={d.box} />
      ))}
    </div>
  );
}

/** Keyboard step of a pane divider, as a fraction of its split. */
const DIVIDER_STEP = 0.05;

function splitRatio(node: Node, id: string): number | undefined {
  if (node.type !== "split") return undefined;
  if (node.id === id) return node.ratio;
  return splitRatio(node.a, id) ?? splitRatio(node.b, id);
}

function Divider({
  id,
  dir,
  rect,
  box,
}: {
  id: string;
  dir: "row" | "col";
  rect: Rect;
  box: Rect;
}) {
  const ws = useWorkspace();

  function onDrag(pos: DragPos, el: HTMLElement) {
    const parent = el.parentElement;
    if (!parent || !ws) return;
    // a nested divider divides its parent's share
    const w = parent.getBoundingClientRect();
    const ratio =
      dir === "row"
        ? (pos.clientX - (w.left + (box.left / 100) * w.width)) / ((box.width / 100) * w.width)
        : (pos.clientY - (w.top + (box.top / 100) * w.height)) / ((box.height / 100) * w.height);
    // a zero-sized workspace (jsdom, a hidden tab) yields NaN or Infinity
    if (Number.isFinite(ratio)) ws.dispatch({ type: "ratio", id, ratio });
  }

  const style: React.CSSProperties =
    dir === "row"
      ? { left: `${rect.left}%`, top: `${rect.top}%`, height: `${rect.height}%` }
      : { top: `${rect.top}%`, left: `${rect.left}%`, width: `${rect.width}%` };

  return (
    <ResizeHandle
      orientation={dir === "row" ? "vertical" : "horizontal"}
      ariaLabel="Resize panes"
      className={"ws-divider " + dir}
      style={style}
      onDrag={onDrag}
      onKeyAdjust={(step) => {
        const ratio = ws ? splitRatio(ws.state.root, id) : undefined;
        if (ws && ratio !== undefined) ws.dispatch({ type: "ratio", id, ratio: ratio + step * DIVIDER_STEP });
      }}
    />
  );
}

function PaneFrame({
  pane,
  rect,
  count,
  ordinal,
  frames,
}: {
  pane: Pane;
  rect: Rect;
  count: number;
  /** 1-based place among the panes of the same view, or 0 when it is the only one. */
  ordinal: number;
  frames: React.MutableRefObject<Map<string, HTMLElement>>;
}) {
  const ws = useWorkspace()!;
  const focused = ws.state.focus === pane.id;
  const only = count === 1;
  const { dispatch } = ws;
  const paneId = pane.id;
  // the change-simulation chat stores its conversation on the pane
  const onConversation = useCallback(
    (conversationId: string | undefined) => dispatch({ type: "set-conversation", id: paneId, conversationId }),
    [dispatch, paneId],
  );

  return (
    <section
      className={"ws-pane" + (focused && !only ? " focused" : "")}
      style={paneStyle(rect)}
      aria-label={`${VIEW_LABEL[pane.view]} pane${ordinal ? ` ${ordinal}` : ""}`}
      ref={(el) => {
        if (el) frames.current.set(pane.id, el);
        else frames.current.delete(pane.id);
      }}
      // any interaction inside the pane makes it the target of the rail and the
      // keyboard shortcuts
      onFocusCapture={() => ws.dispatch({ type: "focus", id: pane.id })}
      onPointerDownCapture={() => ws.dispatch({ type: "focus", id: pane.id })}
    >
      <div className="ws-panebody">
        <AiPaneScope paneId={pane.id}>
        {pane.view === "hst" ? (
          <HstMapPage />
        ) : pane.view === "trace" ? (
          <TracePage />
        ) : pane.view === "map" ? (
          <Suspense fallback={null}>
            <NetworkMapPage initialSite={pane.mapScope} />
          </Suspense>
        ) : pane.view === "diff" ? (
          <Suspense fallback={null}>
            <DiffPage />
          </Suspense>
        ) : pane.view === "sdwan" ? (
          <Suspense fallback={null}>
            <SdwanPage />
          </Suspense>
        ) : pane.view === "equinix" ? (
          <Suspense fallback={null}>
            <EquinixPage />
          </Suspense>
        ) : pane.view === "changesim" ? (
          <Suspense fallback={null}>
            <AnalysisSections current="changesim" />
            <ChangeSimPage conversationId={pane.conversationId} onConversation={onConversation} />
          </Suspense>
        ) : pane.view === "assessments" ? (
          <Suspense fallback={<p role="status">Loading assessments</p>}>
            <AnalysisSections current="assessments" />
            <AssessmentsPage assessmentId={pane.assessmentId} runId={pane.assessmentRunId} draft={pane.assessmentDraft}
              onNavigate={(assessmentId, runId) => ws.dispatch({ type: "open-assessment", id: pane.id, assessmentId, runId })} />
          </Suspense>
        ) : pane.view === "applications" ? (
          <ApplicationPageBoundary key={`${pane.applicationId ?? ""}:${pane.applicationDraft?.generationId ?? ""}`}>
          <Suspense fallback={<p role="status">Loading business applications</p>}>
            <ApplicationsPage applicationId={pane.applicationId} draft={pane.applicationDraft}
              onDraft={(draft) => ws.dispatch({ type: "set-application-draft", id: pane.id, draft })}
              onNavigate={(applicationId) => ws.dispatch({ type: "open-application", id: pane.id, applicationId })}
              onOpenAnalysis={(sessionId) => ws.dispatch({ type: "open-analysis", id: pane.id, sessionId, mode: "connection" })} />
          </Suspense>
          </ApplicationPageBoundary>
        ) : pane.view === "analysis" ? (
          <Suspense fallback={<p role="status">Loading analysis</p>}>
            <AnalysisSections current="analysis" />
            <AnalysisWorkspace sessionId={pane.analysisSessionId}
              section={pane.analysisSection}
              onSection={(section) => ws.dispatch({ type: "set-analysis-section", id: pane.id, section })}
              runId={pane.analysisRunId}
              onRun={(runId) => ws.dispatch({ type: "set-analysis-run", id: pane.id, runId })}
              legacyAssessmentId={pane.assessmentId} legacyRunId={pane.assessmentRunId}
              legacySimulation={pane.analysisMode === "simulation"}
              conversationId={pane.conversationId} onConversation={onConversation}
              onNavigate={(sessionId) => ws.dispatch({ type: "open-analysis", id: pane.id, sessionId, mode: pane.analysisMode })}
              onNavigateLegacy={(assessmentId, runId) => ws.dispatch({ type: "open-analysis-assessment", id: pane.id, assessmentId, runId })} />
          </Suspense>
        ) : (
          <ExplorePage queryKey={pane.queryKey} cypher={pane.cypher} queryParams={pane.queryParams}
            searchText={pane.searchText} nodeUid={pane.nodeUid} searchNonce={pane.searchNonce}
            queryNonce={pane.queryNonce}
            onAsk={(queryKey, params) => ws.dispatch({ type: "open-query", id: pane.id, queryKey, params })} />
        )}
        </AiPaneScope>
      </div>
    </section>
  );
}
