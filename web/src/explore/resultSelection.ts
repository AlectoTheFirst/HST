/**
 * The selection a result card shares between its views.
 *
 * Picked rows are the rows the user selected in the table. The focused node is
 * the one node the user selected in the tree or in the picture. The two are
 * separate: a row pick clears the focus, and a node focus leaves the picked rows
 * as they are. The table marks the hit rows of the focused node, the rows whose
 * row node index holds it.
 *
 * The rules are pure functions so they are tested without React. The hook only
 * holds the state for one run; the owner keys it on the run.
 */

import { useCallback, useMemo, useState } from "react";
import type { ResultRow } from "../api/types";

export type PickMode = "one" | "range" | "toggle";

export interface SelectionState {
  picked: ReadonlySet<number>;
  anchor: number | null;
  focus: string | null;
}

export const EMPTY_SELECTION: SelectionState = { picked: new Set(), anchor: null, focus: null };

/** A row can be picked only when the server told which nodes it touched. */
export function pickable(row: ResultRow | undefined): boolean {
  return !!row?.nodes && row.nodes.length > 0;
}

/** True when at least one row carries a row node index. */
export function hasRowLinks(rows: readonly ResultRow[]): boolean {
  return rows.some((r) => r.nodes !== undefined);
}

/**
 * The next state after a pick of row `index`.
 *   - one: that row only, and the focus is cleared;
 *   - range: adds every pickable row from the anchor to `index`;
 *   - toggle: adds or removes that row.
 * A row that cannot be picked changes nothing.
 */
export function pick(state: SelectionState, rows: readonly ResultRow[], index: number, mode: PickMode): SelectionState {
  if (!pickable(rows[index])) return state;
  if (mode === "one") return { picked: new Set([index]), anchor: index, focus: null };
  if (mode === "toggle") {
    const next = new Set(state.picked);
    if (next.has(index)) next.delete(index);
    else next.add(index);
    return { ...state, picked: next, anchor: index };
  }
  const from = state.anchor ?? index;
  const [lo, hi] = from <= index ? [from, index] : [index, from];
  const next = new Set(state.picked);
  for (let i = lo; i <= hi; i++) if (pickable(rows[i])) next.add(i);
  return { ...state, picked: next, anchor: state.anchor ?? index };
}

/** For each node id, the rows whose row node index holds it, in row order. */
export function hitIndex(rows: readonly ResultRow[]): Map<string, number[]> {
  const out = new Map<string, number[]>();
  rows.forEach((r, i) => {
    for (const id of r.nodes ?? []) {
      const list = out.get(id);
      if (list) list.push(i);
      else out.set(id, [i]);
    }
  });
  return out;
}

/** The union of the row node indexes of `picked`, in row order, then in the
 *  order of each index. */
export function nodesOf(rows: readonly ResultRow[], picked: ReadonlySet<number>): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const i of [...picked].sort((a, b) => a - b)) {
    for (const id of rows[i]?.nodes ?? []) {
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(id);
    }
  }
  return out;
}

/** The seed nodes of the picture. The nodes of the picked rows, unless the
 *  focus is set and the picture of those seeds does not show it: then the focus
 *  alone. Thus a click on a neighbour in the picture does not redraw it. */
export function seedsFor(rowSeeds: readonly string[], focus: string | null, drawn: (seeds: readonly string[]) => ReadonlySet<string>): string[] {
  if (focus === null) return [...rowSeeds];
  if (rowSeeds.length > 0 && drawn(rowSeeds).has(focus)) return [...rowSeeds];
  return [focus];
}

export interface ResultSelection extends SelectionState {
  /** The rows that hold the focused node. */
  hits: ReadonlySet<number>;
  /** The nodes of the picked rows. */
  rowSeeds: string[];
  rowsOf: (id: string) => number[];
  onPick: (index: number, mode: PickMode) => void;
  /** Pick exactly these rows. The focus stays. */
  pickRows: (indexes: readonly number[]) => void;
  setFocus: (id: string | null) => void;
}

export function useResultSelection(rows: readonly ResultRow[]): ResultSelection {
  const [state, setState] = useState<SelectionState>(EMPTY_SELECTION);
  const index = useMemo(() => hitIndex(rows), [rows]);
  const rowsOf = useCallback((id: string) => index.get(id) ?? [], [index]);
  const onPick = useCallback((i: number, mode: PickMode) => setState((s) => pick(s, rows, i, mode)), [rows]);
  const pickRows = useCallback(
    (indexes: readonly number[]) =>
      setState((s) => {
        const picked = new Set(indexes.filter((i) => pickable(rows[i])));
        return { ...s, picked, anchor: picked.size > 0 ? Math.min(...picked) : null };
      }),
    [rows],
  );
  const setFocus = useCallback((id: string | null) => setState((s) => (s.focus === id ? s : { ...s, focus: id })), []);
  const hits = useMemo(() => new Set(state.focus === null ? [] : rowsOf(state.focus)), [state.focus, rowsOf]);
  const rowSeeds = useMemo(() => nodesOf(rows, state.picked), [rows, state.picked]);
  return { ...state, hits, rowSeeds, rowsOf, onPick, pickRows, setFocus };
}
