/** The server caps the rows at MAX_ROWS in tables.py. */

import { useId, useState } from "react";
import type { QueryResult } from "../api/types";
import { useNamer } from "../shell/deviceNames";
import { pickable, type PickMode } from "./resultSelection";

/** A cell's values: a list of plain values item by item, so the table joins them with commas
 *  and names each device uid on its own; any other value as one item. */
function items(v: unknown): unknown[] {
  return Array.isArray(v) && v.every((x) => x === null || typeof x !== "object") ? v : [v];
}

/** A value as text on one line: a list joins its items with commas and a map lists its `key: value` pairs. A list
 *  or map inside another keeps its brackets, on the same line. No value adds a line break: the cell keeps the line
 *  breaks of a text value only. */
function fmt(v: unknown, nested = false): string {
  if (v === null || v === undefined) return "";
  if (Array.isArray(v)) {
    const inner = v
      .map((x) => fmt(x, true))
      .filter((x) => x !== "")
      .join(", ");
    return nested ? `[${inner}]` : inner;
  }
  if (typeof v === "object") {
    const inner = Object.entries(v as Record<string, unknown>)
      .map(([k, x]) => `${k}: ${fmt(x, true)}`)
      .join(", ");
    return nested ? `{${inner}}` : inner;
  }
  return String(v);
}

/** The row count line, also used by the result card head. */
export function rowCountText(result: QueryResult | null): string {
  const n = result?.data.length ?? 0;
  return result ? `${n} row${n === 1 ? "" : "s"}` : "Result";
}

/**
 * With `onPick`, the rows can be picked: a click picks one row,
 * Shift-click adds the range from the last pick, Ctrl-click or Cmd-click adds or
 * removes one row. The table is then one tab stop: Up and Down move the row
 * cursor, Space picks, Shift+Space adds the range, Ctrl+Space adds or removes.
 * A row without a row node index cannot be picked. `hits` marks the rows of the
 * focused node.
 *
 * `bare` leaves out the row count and the truncation notice, for an owner that
 * shows them in its own head.
 */
export function ResultsTable({ result, picked, hits, onPick, bare = false }: {
  result: QueryResult | null;
  picked?: ReadonlySet<number>;
  hits?: ReadonlySet<number>;
  onPick?: (index: number, mode: PickMode) => void;
  bare?: boolean;
}) {
  // a device uid in a cell shows as the hostname, with the uid in the tooltip
  const name = useNamer();
  const rowCount = result?.data.length ?? 0;
  const idBase = useId();
  const [cursor, setCursor] = useState(0);
  const selectable = !!onPick && !!result && result.data.some((r) => pickable(r));
  const at = Math.min(cursor, Math.max(0, rowCount - 1));

  function onKeyDown(e: React.KeyboardEvent) {
    if (!result || !onPick) return;
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      setCursor(Math.max(0, Math.min(rowCount - 1, at + (e.key === "ArrowDown" ? 1 : -1))));
    } else if (e.key === "Home" || e.key === "End") {
      e.preventDefault();
      setCursor(e.key === "Home" ? 0 : rowCount - 1);
    } else if (e.key === " ") {
      e.preventDefault();
      onPick(at, e.shiftKey ? "range" : e.ctrlKey || e.metaKey ? "toggle" : "one");
    }
  }

  return (
    <div className="results">
      {!bare && <div className="eyebrow tabletitle">{rowCountText(result)}</div>}
      {!bare && result && result.truncated && (
        <div className="results-truncated" role="status">
          More than {rowCount} rows
        </div>
      )}
      {!result || rowCount === 0 ? (
        <div className="tableempty">{result ? "No rows" : "No result"}</div>
      ) : (
        <table
          {...(selectable
            ? {
                role: "grid",
                "aria-multiselectable": true,
                "aria-label": "Result rows",
                tabIndex: 0,
                "aria-activedescendant": `${idBase}-r${at}`,
                onKeyDown,
                className: "rt-selectable",
              }
            : {})}
        >
          <thead>
            <tr>
              {result.columns.map((c) => (
                <th key={c}>{c}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {/* rows are never reordered */}
            {result.data.map((d, i) => (
              <tr
                key={i}
                {...(selectable
                  ? {
                      id: `${idBase}-r${i}`,
                      "aria-selected": picked?.has(i) ?? false,
                      "aria-disabled": pickable(d) ? undefined : true,
                      className: [
                        picked?.has(i) ? "rt-picked" : "",
                        hits?.has(i) ? "rt-hit" : "",
                        i === at ? "rt-cursor" : "",
                        pickable(d) ? "rt-pickable" : "",
                      ].filter(Boolean).join(" ") || undefined,
                      onMouseDown: (e: React.MouseEvent) => {
                        // no text selection on Shift-click
                        if (e.shiftKey) e.preventDefault();
                      },
                      onClick: (e: React.MouseEvent) => {
                        setCursor(i);
                        onPick?.(i, e.shiftKey ? "range" : e.ctrlKey || e.metaKey ? "toggle" : "one");
                      },
                    }
                  : {})}
              >
                {d.row.map((v, j) => {
                  const values = items(v).map((x) => fmt(x)).filter((x) => x !== "");
                  const text = values.join(", ");
                  const shown = values.map(name).join(", ");
                  return (
                    <td key={j} className={j > 0 ? "dim" : undefined} title={shown === text ? undefined : text}>
                      {shown}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
