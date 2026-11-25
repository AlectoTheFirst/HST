/**
 * The arrow keys of a radio group or a tablist. The group is
 * one Tab stop (the chosen item, else the first one); the arrow keys, Home and
 * End move to another item and choose it.
 */

import type { KeyboardEvent } from "react";

const KEYS = new Set(["ArrowRight", "ArrowDown", "ArrowLeft", "ArrowUp", "Home", "End"]);

/** The keydown handler of each item. `role` is the item role; the group is
 *  the nearest radiogroup or tablist around the item. */
export function rovingKeys(role: "radio" | "tab") {
  return (e: KeyboardEvent<HTMLElement>) => {
    if (!KEYS.has(e.key)) return;
    const group = e.currentTarget.closest('[role="radiogroup"], [role="tablist"]');
    if (!group) return;
    const items = [...group.querySelectorAll<HTMLElement>(`[role="${role}"]:not([disabled])`)];
    const at = items.findIndex((item) => item === document.activeElement);
    if (items.length === 0 || at < 0) return;
    e.preventDefault();
    const next =
      e.key === "Home"
        ? 0
        : e.key === "End"
          ? items.length - 1
          : (at + (e.key === "ArrowRight" || e.key === "ArrowDown" ? 1 : -1) + items.length) % items.length;
    items[next].focus();
    items[next].click();
  };
}

/** The tabIndex of one item: 0 for the chosen item, or for the first item
 *  when nothing is chosen, and -1 for the others. */
export function rovingTabIndex(chosen: boolean, index: number, anyChosen: boolean): 0 | -1 {
  return chosen || (!anyChosen && index === 0) ? 0 : -1;
}
