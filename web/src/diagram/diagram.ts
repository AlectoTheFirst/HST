/**
 * Shared pieces of the diagram panes (Map, Sites, SD-WAN, Equinix Fabric).
 */
import type React from "react";

/** The props that make a drawn element open its detail panel from the
 *  keyboard as well as the mouse: a focusable button with a name, activated
 *  by Enter or Space. `pressed` states whether its panel is open. */
export function control(label: string, activate: () => void, pressed?: boolean) {
  return {
    tabIndex: 0,
    role: "button" as const,
    "aria-label": label,
    "aria-pressed": pressed,
    onClick: activate,
    onKeyDown: (e: React.KeyboardEvent) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        activate();
      }
    },
  };
}

/** The bezier between two chips: from the bottom of the upper chip to the top
 *  of the lower one, or an arc above both when they are in one row. `lane`
 *  shifts a parallel line sideways by `gap`. */
export function chipPath(
  a: { x: number; y: number; h: number },
  b: { x: number; y: number; h: number },
  lane = 0,
  gap = 10,
): string {
  const offset = lane * gap * (lane % 2 === 0 ? 1 : -1);
  if (Math.abs(a.y - b.y) < 1) {
    const top = a.y - a.h / 2;
    const lift = top - 50 - lane * gap;
    return `M ${a.x + offset} ${top} C ${a.x + offset} ${lift}, ${b.x - offset} ${lift}, ${b.x - offset} ${top}`;
  }
  const [hi, lo] = a.y < b.y ? [a, b] : [b, a];
  const y1 = hi.y + hi.h / 2;
  const y2 = lo.y - lo.h / 2;
  const mid = (y1 + y2) / 2;
  return `M ${hi.x + offset} ${y1} C ${hi.x + offset} ${mid}, ${lo.x + offset} ${mid}, ${lo.x + offset} ${y2}`;
}
