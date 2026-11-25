import { Fragment, lazy, Suspense, useRef, useState } from "react";
import type { PathResponse } from "../api/types";
import { ResizeHandle, type DragPos } from "../shell/ResizeHandle";
import { readJson, writeJson } from "../shell/storage";
import { PathGraphView } from "./PathGraphView";
import { PathTreeView } from "./PathTreeView";
import type { GraphDirection, HopDetail } from "./pathGraph";
import type { Selection } from "./selection";
import { KEY_STEP } from "./useTraceLayout";
import { useNamer } from "../shell/deviceNames";
import { legOutcome, legWord } from "./verdict";
import { exitText, paneExits } from "./traceResult";

const StrataView = lazy(() =>
  import("./strata/StrataView").then((m) => ({ default: m.StrataView })),
);

export type TraceViewMode = "graph" | "tree" | "strata";

interface TraceViewProps {
  view: TraceViewMode;
  result: PathResponse;
  selection: Selection | null;
  onSelect: (selection: Selection) => void;
  /** Clears the selection; absent on a read-only pane. */
  onClear?: () => void;
  /** Which hops the Graph keeps. */
  detail?: HopDetail;
  /** The direction of the Graph. */
  direction?: GraphDirection;
  /** Orbit start in the 3D view. */
  onNavigate?: () => void;
}

function TraceView({ view, result, selection, onSelect, onClear, detail, direction, onNavigate }: TraceViewProps) {
  // The Graph and the Tree scroll natively and take no onNavigate.
  if (view === "graph") {
    return (
      <PathGraphView
        result={result}
        selection={selection}
        onSelect={onSelect}
        onClear={onClear}
        detail={detail}
        direction={direction}
      />
    );
  }
  if (view === "tree") {
    return <PathTreeView result={result} selection={selection} onSelect={onSelect} />;
  }
  return (
    <Suspense
      fallback={
        <div className="ribbon-outer">
          <div className="ribbon-empty">Loading</div>
        </div>
      }
    >
      <StrataView
        result={result}
        selection={selection}
        onSelect={onSelect}
        onNavigate={onNavigate}
      />
    </Suspense>
  );
}

export function TraceRender(props: TraceViewProps) {
  const name = useNamer();
  const { result } = props;
  // Every pane states a walk that is not true on a line of its own.
  const lines =
    result.hops.length === 0
      ? []
      : result.legs.length === 0
        ? result.result?.answer !== "true"
          ? [`${result.result?.word ?? "no result recorded"}: ${name(result.detail)}`]
          : []
        : [
            ...new Set(
              result.legs
                // a blocked leg shows on its firewall's chip
                .filter((leg) => !leg.blocked && legOutcome(leg) !== "ok")
                .map((leg) => `${legWord(leg)}: ${name(leg.detail)}`),
            ),
          ];
  const exits = paneExits(result);
  return (
    <div className="trace-render">
      {exits.length > 0 && (
        <div className="trace-reach hint" role="status">
          <span className="eyebrow">{result.reach === "split" ? "Left estate per path" : "Left estate"}</span>
          {exits.map((exit) => (
            <span key={exitText(exit)}> {name(exitText(exit))}</span>
          ))}
        </div>
      )}
      {lines.length > 0 && (
        <div className="banner warn" role="status">
          {lines.map((line) => (
            <div className="sub" key={line}>
              {line}
            </div>
          ))}
        </div>
      )}
      <TraceView {...props} />
    </div>
  );
}

/** The key stores the pane heights in pixels, by index. */
const PANES_KEY = "hst.trace.panes";
/** The views' own floor (the `min-height` of `.ribbon-outer`). */
const MIN_PANE = 240;

function clampPane(px: number, stackHeight: number): number {
  const max = stackHeight > 0 ? Math.max(MIN_PANE, stackHeight - MIN_PANE) : Infinity;
  return Math.min(max, Math.max(MIN_PANE, px));
}

/** A read-only pane passes `selection: null` and `ignoreSelect`. */
export interface TracePane {
  key: string;
  heading: string;
  result: PathResponse;
  selection: Selection | null;
  onSelect: (selection: Selection) => void;
  onClear?: () => void;
}

export function ignoreSelect(): void {}

/** A handle sets the pane above it to a pixel height. */
export function TraceGroups({
  panes,
  view,
  detail,
  direction,
  onNavigate,
}: {
  panes: TracePane[];
  view: TraceViewMode;
  detail?: HopDetail;
  direction?: GraphDirection;
  onNavigate: () => void;
}) {
  const [heights, setHeights] = useState<Record<number, number>>(() =>
    readJson<Record<number, number>>(PANES_KEY, {}),
  );
  const stack = useRef<HTMLDivElement | null>(null);
  const paneEls = useRef(new Map<number, HTMLDivElement>());

  function stackHeight(): number {
    return stack.current?.getBoundingClientRect().height ?? 0;
  }

  function paneHeight(index: number): number {
    return paneEls.current.get(index)?.getBoundingClientRect().height ?? 0;
  }

  function setHeight(index: number, px: number | null): Record<number, number> {
    const next = { ...heights };
    if (px === null) delete next[index];
    else next[index] = px;
    setHeights(next);
    return next;
  }

  function onDrag(index: number, pos: DragPos, handle: HTMLElement) {
    const current = paneHeight(index);
    // jsdom reports every rect as zero
    if (current <= 0) return;
    const grip = handle.getBoundingClientRect();
    const px = current + pos.clientY - (grip.top + grip.height / 2);
    setHeight(index, clampPane(px, stackHeight()));
  }

  function adjust(index: number, step: -1 | 1) {
    // the handle moving down grows the pane above it
    const current = heights[index] ?? Math.max(MIN_PANE, paneHeight(index));
    const next = setHeight(index, clampPane(current + step * KEY_STEP, stackHeight()));
    writeJson(PANES_KEY, next);
  }

  function reset(index: number) {
    writeJson(PANES_KEY, setHeight(index, null));
  }

  return (
    <div className="trace-groups" ref={stack}>
      {panes.map((pane, index) => {
        const last = index === panes.length - 1;
        const height = heights[index];
        return (
          <Fragment key={pane.key}>
            <div
              className="trace-group"
              ref={(el) => {
                if (el) paneEls.current.set(index, el);
                else paneEls.current.delete(index);
              }}
              style={last || height === undefined ? undefined : { flex: "0 0 auto", height }}
            >
              <span className="eyebrow">{pane.heading}</span>
              <TraceRender
                view={view}
                result={pane.result}
                selection={pane.selection}
                onSelect={pane.onSelect}
                onClear={pane.onClear}
                detail={detail}
                direction={direction}
                onNavigate={onNavigate}
              />
            </div>
            {!last && (
              <ResizeHandle
                orientation="horizontal"
                ariaLabel={`Resize ${pane.heading} pane`}
                className="trace-resize"
                onDrag={(pos, el) => onDrag(index, pos, el)}
                onCommit={() => writeJson(PANES_KEY, heights)}
                onReset={() => reset(index)}
                onKeyAdjust={(step) => adjust(index, step)}
              />
            )}
          </Fragment>
        );
      })}
    </div>
  );
}
