/**
 * One drag handle, shared by the pane dividers and the trace page's internal
 * split.
 */

import { useRef } from "react";

/** Pointer travel before a press counts as a drag. */
export const DRAG_SLOP = 3;

export interface DragPos {
  clientX: number;
  clientY: number;
}

interface ResizeHandleProps {
  /** "vertical" divides side by side and drags along x; "horizontal" along y. */
  orientation: "vertical" | "horizontal";
  ariaLabel: string;
  className?: string;
  style?: React.CSSProperties;
  /** Called for every drag move past the slop, with the handle element. */
  onDrag: (pos: DragPos, el: HTMLElement) => void;
  /** Pointer-up after a drag past the slop. */
  onCommit?: () => void;
  /** Double-click. */
  onReset?: () => void;
  /** Arrow keys: -1 toward the top/left, +1 toward the bottom/right. */
  onKeyAdjust?: (step: -1 | 1) => void;
  ariaValueNow?: number;
  ariaValueMin?: number;
  ariaValueMax?: number;
}

export function ResizeHandle({
  orientation,
  ariaLabel,
  className,
  style,
  onDrag,
  onCommit,
  onReset,
  onKeyAdjust,
  ariaValueNow,
  ariaValueMin,
  ariaValueMax,
}: ResizeHandleProps) {
  const drag = useRef<{ start: number; moved: boolean } | null>(null);
  const axis = (e: DragPos) => (orientation === "vertical" ? e.clientX : e.clientY);

  function onPointerDown(e: React.PointerEvent<HTMLDivElement>) {
    if (e.button !== 0) return;
    drag.current = { start: axis(e), moved: false };
    e.currentTarget.setPointerCapture?.(e.pointerId);
  }

  function onPointerMove(e: React.PointerEvent<HTMLDivElement>) {
    const d = drag.current;
    if (!d) return;
    if (!d.moved && Math.abs(axis(e) - d.start) < DRAG_SLOP) return;
    d.moved = true;
    onDrag({ clientX: e.clientX, clientY: e.clientY }, e.currentTarget);
  }

  function onPointerUp(e: React.PointerEvent<HTMLDivElement>) {
    const d = drag.current;
    if (e.currentTarget.hasPointerCapture?.(e.pointerId)) {
      e.currentTarget.releasePointerCapture(e.pointerId);
    }
    drag.current = null;
    if (d?.moved) onCommit?.();
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLDivElement>) {
    if (!onKeyAdjust) return;
    const back = orientation === "vertical" ? "ArrowLeft" : "ArrowUp";
    const forward = orientation === "vertical" ? "ArrowRight" : "ArrowDown";
    if (e.key !== back && e.key !== forward) return;
    e.preventDefault();
    onKeyAdjust(e.key === back ? -1 : 1);
  }

  return (
    // The ARIA window-splitter separator is interactive.
    // eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions
    <div
      className={className}
      role="separator"
      aria-orientation={orientation}
      aria-label={ariaLabel}
      aria-valuenow={ariaValueNow}
      aria-valuemin={ariaValueMin}
      aria-valuemax={ariaValueMax}
      // The ARIA window-splitter separator is focusable.
      // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex
      tabIndex={onKeyAdjust ? 0 : undefined}
      style={style}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      onPointerCancel={onPointerUp}
      onDoubleClick={onReset}
      onKeyDown={onKeyDown}
    />
  );
}
