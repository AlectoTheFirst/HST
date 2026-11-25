import { useWorkspace } from "../workspace/WorkspaceContext";
import { traceDraft } from "../assessments/context";
import { TraceConnectionActions } from "../applications/TraceConnectionActions";

import { useMemo, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { api, ApiError, mtuQueryParams } from "../api/client";
import type { PathResponse } from "../api/types";
import { handOff } from "../hst/route/handoff";
import { ResizeHandle } from "../shell/ResizeHandle";
import { readJson, writeJson } from "../shell/storage";
import { Composer, type TraceParams } from "./Composer";
import { useNamer } from "../shell/deviceNames";
import { Inspector } from "./Inspector";
import { TraceInfo } from "./TraceInfo";
import { defaultSelection, type Selection } from "./selection";
import { formatSnapshotDate } from "./SnapshotPicker";
import { useAiContext, useAiPaneId } from "../ai/context";
import { TraceGroups, TraceRender, ignoreSelect, type TraceViewMode } from "./TraceGroups";
import {
  groupByInterpretation,
  isBidirectional,
  isCompare,
  replyPanes,
  traceContext,
  type TraceRequest,
  type TraceResult,
} from "./traceResult";
import { useTraceLayout } from "./useTraceLayout";
import type { GraphDirection, HopDetail } from "./pathGraph";

const VIEW_KEY = "hst.trace.view";
const DIRECTION_KEY = "hst.trace.direction";

function readDirection(): GraphDirection {
  return readJson<string>(DIRECTION_KEY, "tb") === "lr" ? "lr" : "tb";
}

/** A stored "ledger" opens the Tree. */
function readView(): TraceViewMode {
  const stored = readJson<string>(VIEW_KEY, "graph");
  if (stored === "tree" || stored === "ledger") return "tree";
  if (stored === "strata") return "strata";
  return "graph";
}

async function fetchPath(params: TraceRequest): Promise<TraceResult> {
  const query = new URLSearchParams({ src: params.src, dst: params.dst, proto: params.proto });
  mtuQueryParams(params.mtu).forEach((value, key) => query.set(key, value));
  if (params.port) query.set("port", params.port);
  if (params.snapshot) query.set("snapshot", params.snapshot);
  if (params.startVrf) query.set("start_vrf", params.startVrf);
  // GET /api/path answers 400 to reply and snapshot_b together.
  if (params.reply) {
    query.set("reply", "true");
  } else if (params.compareWith) {
    query.set("snapshot_b", params.compareWith);
  }
  return api<TraceResult>(`/path?${query.toString()}`);
}

export default function TracePage() {
  const workspace = useWorkspace();
  const [selection, setSelection] = useState<Selection | null>(null);
  const [view, setView] = useState<TraceViewMode>(readView);
  const [detail, setDetail] = useState<HopDetail>("devices");
  const [direction, setDirection] = useState<GraphDirection>(readDirection);

  function chooseDirection(next: GraphDirection) {
    setDirection(next);
    writeJson(DIRECTION_KEY, next);
  }
  const {
    page,
    bottom,
    infoOpen,
    inspectorOpen,
    setInfoOpen,
    setInspectorOpen,
    collapse,
    onResizeDrag,
    adjust,
    commitBottom,
    resetBottom,
  } = useTraceLayout();

  function chooseView(next: TraceViewMode) {
    setView(next);
    writeJson(VIEW_KEY, next);
  }

  function handleNavigate() {
    collapse();
  }

  const name = useNamer();
  const mutation = useMutation<TraceResult, ApiError, TraceRequest>({
    mutationFn: fetchPath,
  });

  function handleTrace(params: TraceParams) {
    setSelection(null);
    collapse();
    mutation.mutate({ ...params, reply: params.reply ?? false });
  }

  function handleSelect(next: Selection) {
    setSelection(next);
    setInspectorOpen(true);
  }

  function handleClear() {
    setSelection(null);
  }

  const raw = mutation.data ?? null;
  const compare = raw && isCompare(raw) ? raw : null;
  const bidirectional = raw && isBidirectional(raw) ? raw : null;
  const data = compare ? compare.a.result : bidirectional ? bidirectional.forward : (raw as PathResponse | null);
  const request = mutation.variables;
  useAiContext(
    useAiPaneId(),
    request ? traceContext(request, compare?.a.snapshot ?? data?.run?.snapshot, selection, data?.hops ?? []) : null,
  );
  // a 200 with no hops is "no path"
  const assessmentDraft = mutation.variables && data ? traceDraft(mutation.variables, compare?.a.snapshot ?? data.run?.snapshot ?? mutation.variables.snapshot) : null;
  const noPath = !!data && data.hops.length === 0;
  const result = data && !noPath ? data : null;
  // StrataView builds its WebGL stage per `result` object.
  const groups = useMemo(
    () => (result && !compare && !bidirectional ? groupByInterpretation(result) : null),
    [result, compare, bidirectional],
  );
  const errorMessage = mutation.isError
    ? mutation.error instanceof ApiError
      ? mutation.error.message
      : "Trace failed"
    : noPath
      ? data!.detail
      : null;
  const bottomCollapsed = !!result && !infoOpen && !inspectorOpen;

  return (
    <div className="trace-page" ref={page}>
      <Composer
        onTrace={handleTrace}
        tracing={mutation.isPending}
        advancedExtra={
          workspace && assessmentDraft && !mutation.isPending ? (
            <div className="assessment-actions"><button
              type="button"
              className="secondary"
              onClick={() => workspace.openAssessments(undefined, undefined, assessmentDraft)}
            >Investigate evidence</button><TraceConnectionActions draft={assessmentDraft}
              onOpenAnalysis={(id) => workspace.openAnalysis(id, "connection")}
              onOpenApplication={(id) => workspace.openApplications(id)} /></div>
          ) : null
        }
      />
      {errorMessage && (
        <div className="banner err" role="alert">
          <div className="sub">{errorMessage}</div>
        </div>
      )}
      {bidirectional && bidirectional.notes.length > 0 && (
        <div className="banner warn" role="status">
          {bidirectional.notes.map((note, i) => (
            <div className="sub" key={i}>
              {name(note)}
            </div>
          ))}
        </div>
      )}
      <div className="trace-view-toggle">
        {result && workspace && (
          <button
            type="button"
            className="trace-show-on-map"
            onClick={() => {
              handOff(result, compare?.a.snapshot ?? result.run?.snapshot ?? null);
              workspace.openView("hst");
            }}
          >
            Show on map
          </button>
        )}
        <div className="tabs" role="group" aria-label="Trace view">
          {(
            [
              ["graph", "Graph"],
              ["tree", "Tree"],
              ["strata", "3D"],
            ] as const
          ).map(([mode, label]) => (
            <button
              key={mode}
              type="button"
              aria-pressed={view === mode}
              className={view === mode ? "on" : undefined}
              onClick={() => chooseView(mode)}
            >
              {label}
            </button>
          ))}
        </div>
        {view === "graph" && (
          <div className="segs trace-detail" role="group" aria-label="Hop detail">
            {(
              [
                ["devices", "Devices"],
                ["all", "All hops"],
              ] as const
            ).map(([mode, label]) => (
              <button
                key={mode}
                type="button"
                aria-pressed={detail === mode}
                className={detail === mode ? "on" : undefined}
                onClick={() => setDetail(mode)}
              >
                {label}
              </button>
            ))}
          </div>
        )}
        {view === "graph" && (
          <div className="segs trace-detail" role="group" aria-label="Direction">
            {(
              [
                ["tb", "Top down"],
                ["lr", "Left to right"],
              ] as const
            ).map(([mode, label]) => (
              <button
                key={mode}
                type="button"
                aria-pressed={direction === mode}
                className={direction === mode ? "on" : undefined}
                onClick={() => chooseDirection(mode)}
              >
                {label}
              </button>
            ))}
          </div>
        )}
      </div>
      {/* The canvas and the details block. Stacked in a narrow pane with the
          drag handle between them; side by side in a wide one (theme.css, the
          `.trace-body` container query). */}
      <div className="trace-body">
      {result ? (
        compare ? (
          <TraceGroups
            view={view}
            detail={detail}
            direction={direction}
            onNavigate={handleNavigate}
            panes={[
              {
                key: "a",
                heading: formatSnapshotDate(Number(compare.a.snapshot)),
                result: compare.a.result,
                selection,
                onSelect: handleSelect,
                onClear: handleClear,
              },
              // The shared Inspector is bound to A's result.
              {
                key: "b",
                heading: formatSnapshotDate(Number(compare.b.snapshot)),
                result: compare.b.result,
                selection: null,
                onSelect: ignoreSelect,
              },
            ]}
          />
        ) : bidirectional ? (
          <TraceGroups
            view={view}
            detail={detail}
            direction={direction}
            onNavigate={handleNavigate}
            panes={[
              {
                key: "forward",
                heading: "Forward",
                result: bidirectional.forward,
                selection,
                onSelect: handleSelect,
                onClear: handleClear,
              },
              // The shared Inspector is bound to the forward direction.
              ...replyPanes(bidirectional).map((pane) => ({
                ...pane,
                selection: null,
                onSelect: ignoreSelect,
              })),
            ]}
          />
        ) : groups ? (
          <TraceGroups
            view={view}
            detail={detail}
            direction={direction}
            onNavigate={handleNavigate}
            panes={groups.map((g) => ({ ...g, selection, onSelect: handleSelect, onClear: handleClear }))}
          />
        ) : (
          <TraceRender
            view={view}
            result={result}
            selection={selection}
            onSelect={handleSelect}
            onClear={handleClear}
            detail={detail}
            direction={direction}
            onNavigate={handleNavigate}
          />
        )
      ) : (
        <div className="ribbon-outer">
          <div className="ribbon-empty">
            {mutation.isPending ? "Tracing" : null}
          </div>
        </div>
      )}
      {!bottomCollapsed && (
        <ResizeHandle
          orientation="horizontal"
          ariaLabel="Resize trace details"
          className="trace-resize"
          onDrag={onResizeDrag}
          onCommit={commitBottom}
          onReset={resetBottom}
          onKeyAdjust={adjust}
        />
      )}
      <div
        className="trace-bottom"
        style={bottomCollapsed || bottom === null ? undefined : { height: bottom }}
      >
        <TraceInfo result={result} open={infoOpen} onToggle={() => setInfoOpen(!infoOpen)} />
        <Inspector
          selection={selection ?? defaultSelection(result)}
          result={result}
          open={inspectorOpen}
          onToggle={() => setInspectorOpen(!inspectorOpen)}
        />
      </div>
      </div>
    </div>
  );
}
