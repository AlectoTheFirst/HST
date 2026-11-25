/**
 * TracePage's persisted layout.
 */

import { useRef, useState } from "react";
import type { DragPos } from "../shell/ResizeHandle";
import { readJson, writeJson } from "../shell/storage";

/** Height of the details block in pixels, or `null` for the natural height. */
const BOTTOM_KEY = "hst.trace.bottom";
const DEFAULT_BOTTOM = 200;
const MIN_BOTTOM = 80;
/** Minimum height of the trace view above the details block. */
const RIBBON_FLOOR = 320;
/** Pixels one arrow key moves a resize handle. */
export const KEY_STEP = 24;

/** Both blocks default to collapsed. */
const INFO_OPEN_KEY = "hst.trace.info.open";
const INSPECTOR_OPEN_KEY = "hst.trace.inspector.open";

export function clampBottom(px: number, pageHeight: number): number {
  const max = pageHeight > 0 ? Math.max(MIN_BOTTOM, pageHeight - RIBBON_FLOOR) : Infinity;
  return Math.min(max, Math.max(MIN_BOTTOM, px));
}


export function useTraceLayout() {
  const [bottom, setBottom] = useState<number | null>(() => readJson<number | null>(BOTTOM_KEY, null));
  const [infoOpen, setInfoOpenState] = useState<boolean>(() => readJson<boolean>(INFO_OPEN_KEY, false));
  const [inspectorOpen, setInspectorOpenState] = useState<boolean>(() =>
    readJson<boolean>(INSPECTOR_OPEN_KEY, false),
  );
  const page = useRef<HTMLDivElement | null>(null);

  function setInfoOpen(next: boolean) {
    setInfoOpenState(next);
    writeJson(INFO_OPEN_KEY, next);
  }

  function setInspectorOpen(next: boolean) {
    setInspectorOpenState(next);
    writeJson(INSPECTOR_OPEN_KEY, next);
  }

  /** Fold both blocks down. */
  function collapse() {
    setInfoOpen(false);
    setInspectorOpen(false);
  }

  function pageHeight(): number {
    return page.current?.getBoundingClientRect().height ?? 0;
  }

  function onResizeDrag(pos: DragPos) {
    const rect = page.current?.getBoundingClientRect();
    // jsdom reports every rect as zero
    if (!rect || rect.height <= 0) return;
    setBottom(clampBottom(rect.bottom - pos.clientY, rect.height));
  }

  function adjust(step: -1 | 1) {
    // the handle moving up grows the block below it
    const next = clampBottom((bottom ?? DEFAULT_BOTTOM) - step * KEY_STEP, pageHeight());
    setBottom(next);
    writeJson(BOTTOM_KEY, next);
  }

  function commitBottom() {
    writeJson(BOTTOM_KEY, bottom);
  }

  function resetBottom() {
    setBottom(null);
    writeJson(BOTTOM_KEY, null);
  }

  return {
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
  };
}
