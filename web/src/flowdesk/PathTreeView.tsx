/** The filter dims the rows that do not match. */

import { useId, useMemo, useRef, useState, type KeyboardEvent, type MouseEvent } from "react";
import type { PathResponse } from "../api/types";
import { isGate } from "./gate";
import { MONO_KINDS, isSelectedHop, kindColor, kindVar } from "./hopStyle";
import { MtuHopSummary, MtuLegSummary, mtuForLane } from "./MtuPanel";
import { hopId } from "./pathGraph";
import { buildPathTree, itemHop, laneOutcome, rowText, treeRows, treeText, type TreeRow } from "./pathTree";
import type { Selection } from "./selection";
import { VERDICT_WORD, legWord } from "./verdict";

function isRowSelected(row: TreeRow, selection: Selection | null): boolean {
  if (!selection) return false;
  if (row.type === "item") {
    if (selection.type !== "hop") return false;
    const id = hopId(selection.data);
    return [...row.node.hopByLane.values()].some((h) => hopId(h) === id);
  }
  if (row.type === "hop") return isSelectedHop(selection, row.hop);
  return selection.type === "leg" && selection.data.lane === row.lane;
}

export function PathTreeView({
  result,
  selection,
  onSelect,
}: {
  result: PathResponse;
  selection: Selection | null;
  onSelect: (selection: Selection) => void;
}) {
  const tree = useMemo(() => buildPathTree(result), [result]);
  const [open, setOpen] = useState<ReadonlySet<string>>(() => new Set());
  const [cursor, setCursor] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const filterRef = useRef<HTMLInputElement | null>(null);
  const treeRef = useRef<HTMLDivElement | null>(null);
  const domId = useId();

  const legLine = useMemo(() => (lane: number) => mtuForLane(result.mtu, lane) !== null, [result.mtu]);
  const rows = useMemo(() => treeRows(tree, open, legLine), [tree, open, legLine]);

  if (!result.hops.length) {
    return (
      <div className="ribbon-outer">
        <div className="ribbon-empty">{result.detail || "no path to draw"}</div>
      </div>
    );
  }

  const itemIds = treeRows(tree, new Set(), legLine)
    .filter((r) => r.type === "item" && r.hasDetail)
    .map((r) => r.id);
  const allOpen = itemIds.length > 0 && itemIds.every((id) => open.has(id));
  const curIndex = Math.max(0, rows.findIndex((r) => r.id === cursor));
  const current = rows[curIndex];
  const needle = filter.trim().toLowerCase();
  const rowDomId = (i: number) => `${domId}-row-${i}`;

  function select(row: TreeRow) {
    setCursor(row.id);
    if (row.type === "item") onSelect({ type: "hop", data: itemHop(row.node) });
    else if (row.type === "hop") onSelect({ type: "hop", data: row.hop });
    else {
      const leg = tree.legByLane.get(row.lane);
      if (leg) onSelect({ type: "leg", data: leg });
    }
  }

  function toggle(id: string, want?: boolean) {
    setOpen((prev) => {
      const next = new Set(prev);
      const on = want ?? !prev.has(id);
      if (on) next.add(id);
      else next.delete(id);
      return next;
    });
  }

  function copy() {
    void navigator.clipboard?.writeText(treeText(tree, rows)).catch(() => {});
  }

  function onKey(e: KeyboardEvent<HTMLDivElement>) {
    if (!current) return;
    let to: TreeRow | undefined;
    switch (e.key) {
      case "j":
      case "ArrowDown":
        to = rows[Math.min(rows.length - 1, curIndex + 1)];
        break;
      case "k":
      case "ArrowUp":
        to = rows[Math.max(0, curIndex - 1)];
        break;
      case "l":
      case "ArrowRight":
        if (current.type === "item" && current.hasDetail) toggle(current.id, true);
        break;
      case "h":
      case "ArrowLeft":
        if (current.type === "item" && open.has(current.id)) toggle(current.id, false);
        else if (current.type !== "item") {
          toggle(current.parent, false);
          to = rows.find((r) => r.id === current.parent);
        } else {
          for (let i = curIndex - 1; i >= 0; i--) {
            const r = rows[i];
            if (r.type === "item" && r.node.kids.length > 1) {
              to = r;
              break;
            }
          }
        }
        break;
      case "y":
        copy();
        break;
      case "/":
        e.preventDefault();
        filterRef.current?.focus();
        return;
      default:
        return;
    }
    e.preventDefault();
    if (to && to !== current) select(to);
  }

  function onRowClick(e: MouseEvent<HTMLDivElement>, row: TreeRow) {
    if (row.type === "item" && row.hasDetail && (e.target as HTMLElement).closest(".pt-tog")) toggle(row.id);
    select(row);
    treeRef.current?.focus();
  }

  return (
    <div className="pt-outer">
      <div className="pt-bar">
        <input
          ref={filterRef}
          className="pt-filter"
          type="search"
          placeholder="Filter"
          aria-label="Filter"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Escape") treeRef.current?.focus();
          }}
        />
        <button
          type="button"
          className="pt-btn"
          disabled={itemIds.length === 0}
          onClick={() => setOpen(allOpen ? new Set() : new Set(itemIds))}
        >
          {allOpen ? "Close all hops" : "Open all hops"}
        </button>
        <button type="button" className="pt-btn" onClick={copy}>
          Copy as text
        </button>
      </div>
      <div
        ref={treeRef}
        className="pt-tree"
        role="tree"
        tabIndex={0}
        aria-label="Path tree"
        aria-activedescendant={current ? rowDomId(curIndex) : undefined}
        onKeyDown={onKey}
      >
        {rows.map((row, i) => {
          const hit = needle !== "" && rowText(row, tree).toLowerCase().includes(needle);
          const cls = [
            "pt-row",
            i === curIndex ? "cur" : "",
            isRowSelected(row, selection) ? "selected" : "",
            needle ? (hit ? "match" : "dim") : "",
          ]
            .filter(Boolean)
            .join(" ");
          return (
            // the tree holds the key handler and moves aria-activedescendant
            // eslint-disable-next-line jsx-a11y/click-events-have-key-events
            <div
              key={row.id}
              id={rowDomId(i)}
              className={cls}
              role="treeitem"
              tabIndex={-1}
              aria-level={row.level}
              aria-selected={isRowSelected(row, selection)}
              aria-expanded={row.type === "item" && row.hasDetail ? open.has(row.id) : undefined}
              onClick={(e) => onRowClick(e, row)}
            >
              <span className="pt-pfx">{row.prefix}</span>
              <RowBody row={row} open={open.has(row.id)} result={result} tree={tree} />
            </div>
          );
        })}
      </div>
    </div>
  );
}

function RowBody({
  row,
  open,
  result,
  tree,
}: {
  row: TreeRow;
  open: boolean;
  result: PathResponse;
  tree: ReturnType<typeof buildPathTree>;
}) {
  if (row.type === "hop") {
    const h = row.hop;
    return (
      <>
        {row.multi && <span className="pt-pn">Path {row.lane + 1}</span>}
        <span className="pt-mark" style={{ background: kindColor(h.kind) }} aria-hidden="true" />
        <span className={"pt-hname" + (MONO_KINDS.has(h.kind) ? " mono" : "")}>{h.label}</span>
        <span className="pt-kind">{h.kind}</span>
        {h.note && <span className="pt-note">{h.note}</span>}
        <MtuHopSummary result={result.mtu} hop={h} />
      </>
    );
  }
  if (row.type === "leg") {
    return (
      <>
        {row.multi && <span className="pt-pn">Path {row.lane + 1}</span>}
        <MtuLegSummary result={result.mtu} lane={row.lane} />
      </>
    );
  }
  const { node } = row;
  const hop = itemHop(node);
  const gate = isGate(hop);
  return (
    <>
      <span className="pt-tog">{row.hasDetail ? (open ? "[-]" : "[+]") : "   "}</span>
      <span
        className={"pt-mark" + (gate ? " gate" : "")}
        style={gate ? kindVar(hop.kind) : { background: kindColor(hop.kind) }}
        aria-hidden="true"
      />
      <span className={"pt-name" + (MONO_KINDS.has(hop.kind) ? " mono" : "")}>{hop.label}</span>
      {!gate && <span className="pt-kind">{hop.kind}</span>}
      {node.verdict && <span className={"pt-pill " + node.verdict}>{VERDICT_WORD[node.verdict]}</span>}
      {hop.note && <span className="pt-note">{hop.note}</span>}
      {node.ecmp && <span className="pt-tag">ECMP {node.kids.length}</span>}
      {node.ends.map((lane) => {
        const leg = tree.legByLane.get(lane);
        return (
          <span key={lane} className="pt-end">
            <span className="pt-tag">Path {lane + 1}</span>
            {leg && (
              <span className={"pt-pill " + laneOutcome(tree, lane)} title={leg.detail}>
                {legWord(leg)}
              </span>
            )}
          </span>
        );
      })}
    </>
  );
}
