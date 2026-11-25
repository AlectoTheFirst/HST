/**
 * The Tree view of a query result.
 *
 * The rules live in treeModel.ts. This component holds the open set, the
 * snapshot loads, the cursor and the filter, and draws the flat item list of
 * `buildRows` with the WAI-ARIA tree pattern. The keys work only while the tree
 * has the focus; it adds no global key handler.
 *
 * The tree mounts when the user selects the Tree view. If rows are picked then,
 * it opens the path from each row root to the other nodes of the row.
 */

import { useEffect, useId, useMemo, useRef, useState } from "react";
import { useQueries } from "@tanstack/react-query";
import { exploreApi } from "../api/explore";
import type { ResultGraph, ResultRow } from "../api/types";
import { captionFull, primaryLabel } from "./graphElements";
import type { Palette } from "./graphStyle";
import { layerOf } from "./lanes";
import type { ResultSelection } from "./resultSelection";
import { message } from "./SearchView";
import {
  buildRows,
  branchText,
  countText,
  filterTree,
  keepFiltered,
  groupText,
  itemText,
  RESULT_PAGE,
  reveal,
  revealNode,
  SNAPSHOT_PAGE,
  summary,
  type Adjacency,
  type DetailState,
  type PageState,
  type TreeInput,
  type TreeItem,
} from "./treeModel";
import { LabelChip, SlotMark } from "./slotMark";
import "./resulttree.css";

const EMPTY: ReadonlySet<string> = new Set();

/** The node id at the end of an item key, when the key ends on a node. */
function nodeOfKey(key: string): string | null {
  const last = key.split("|").pop() ?? "";
  return last.startsWith("n:") ? last.slice(2) : null;
}

function parseGid(gid: string): { type: string; direction: "out" | "in"; label?: string } {
  const [type, direction, ...rest] = gid.split(":");
  const label = rest.join(":");
  return { type, direction: direction === "in" ? "in" : "out", label: label || undefined };
}

export function ResultTree({
  rows,
  graph,
  adj,
  roots,
  rowsOfRoot,
  resultRels,
  sel,
  full,
  slotOf,
  palette,
  onGraph,
  onOpen,
  objectPanel,
}: {
  rows: readonly ResultRow[];
  graph: ResultGraph;
  adj: Adjacency;
  roots: readonly string[];
  rowsOfRoot: ReadonlyMap<string, number[]>;
  resultRels: ReadonlySet<string>;
  sel: ResultSelection;
  /** The view graph is at its node cap. */
  full: boolean;
  slotOf: (label: string) => number;
  palette: Palette;
  onGraph: (payload: ResultGraph) => void;
  onOpen: (uid: string) => void;
  objectPanel?: (node: { labels: string[]; properties: Record<string, unknown> }) => React.ReactNode;
}) {
  const base = useId();
  const treeRef = useRef<HTMLDivElement>(null);
  const filterRef = useRef<HTMLInputElement>(null);

  // The first state: the reveal of the picked rows, else the first root open.
  const [initial] = useState(() => {
    const picked = [...sel.picked].sort((a, b) => a - b);
    const open = new Set<string>();
    const pinned = new Set<string>();
    let cursor: string | null = null;
    for (const i of picked) {
      const nodes = (rows[i]?.nodes ?? []).filter((id) => adj.nodes.has(id));
      const root = nodes[0];
      if (root === undefined) continue;
      const r = reveal(adj, roots, root, nodes.slice(1));
      r.open.forEach((k) => open.add(k));
      r.pinned.forEach((k) => pinned.add(k));
      cursor ??= `n:${root}`;
    }
    if (picked.length === 0 && roots[0] !== undefined) open.add(`n:${roots[0]}`);
    return { open, pinned, cursor };
  });
  const [open, setOpen] = useState<ReadonlySet<string>>(initial.open);
  const [pinned, setPinned] = useState<ReadonlySet<string>>(initial.pinned);
  const [cursor, setCursor] = useState<string | null>(initial.cursor);
  const [limits, setLimits] = useState<ReadonlyMap<string, number>>(new Map());
  const [pages, setPages] = useState<ReadonlyMap<string, PageState>>(new Map());
  const [filter, setFilter] = useState("");
  const [status, setStatus] = useState("");
  const [fallback, setFallback] = useState<string | null>(null);

  // The node details of the open nodes, with the same query key as the Search
  // tab and the canvas, so the cache is shared.
  const uids = useMemo(() => {
    const out: string[] = [];
    for (const key of open) {
      const id = nodeOfKey(key);
      const uid = id ? adj.nodes.get(id)?.properties.uid : undefined;
      if (typeof uid === "string" && uid && !out.includes(uid)) out.push(uid);
    }
    return out;
  }, [open, adj]);
  const details = useQueries({
    queries: uids.map((uid) => ({ queryKey: ["explore", "node", uid], queryFn: () => exploreApi.node(uid) })),
  });
  const detailOf = useMemo(() => {
    const map = new Map<string, { state: DetailState; refetch: () => void }>();
    uids.forEach((uid, i) => {
      const q = details[i];
      const state: DetailState = q.data
        ? { status: "ok", groups: q.data.neighbors }
        : q.isError
          ? { status: "error", message: message(q.error) }
          : { status: "loading" };
      map.set(uid, { state, refetch: () => void q.refetch() });
    });
    return map;
  }, [uids, details]);

  const input: TreeInput = useMemo(
    () => ({
      adj,
      roots,
      rowsOfRoot,
      resultRels,
      detail: (uid) => detailOf.get(uid)?.state,
      page: (uid, gid) => pages.get(`${uid}|${gid}`),
      open,
      limits,
      full,
    }),
    [adj, roots, rowsOfRoot, resultRels, detailOf, pages, open, limits, full],
  );
  const filtered = useMemo(() => filterTree(input, filter), [input, filter]);
  const filtering = filter.trim() !== "";
  const items = useMemo(() => {
    const pins = filtering ? new Set([...pinned, ...filtered.onPath]) : pinned;
    const rows = buildRows(input, filtering ? filtered.open : EMPTY, pins);
    return filtering ? keepFiltered(rows, filtered) : rows;
  }, [input, filtering, filtered, pinned]);

  const indexOf = useMemo(() => new Map(items.map((it, i) => [it.key, i])), [items]);
  const guides = useMemo(() => {
    const last: boolean[] = [];
    return items.map((it) => {
      last[it.level] = it.posinset === it.setsize;
      if (it.level === 1) return "";
      let g = "";
      for (let l = 2; l < it.level; l++) g += last[l] ? "    " : "|   ";
      return g + (last[it.level] ? "`-- " : "|-- ");
    });
  }, [items]);
  const at = cursor !== null && indexOf.has(cursor) ? indexOf.get(cursor)! : 0;
  const current: TreeItem | undefined = items[at];

  // A focus from the picture moves the cursor to the first copy of the node,
  // and opens a path to it when no copy is visible.
  const [seenFocus, setSeenFocus] = useState(sel.focus);
  if (sel.focus !== seenFocus) {
    setSeenFocus(sel.focus);
    if (sel.focus !== null && current?.nodeId !== sel.focus) {
      const copy = items.find((it) => it.kind === "node" && it.nodeId === sel.focus);
      if (copy) setCursor(copy.key);
      else {
        const r = revealNode(adj, roots, sel.focus);
        if (r) {
          setOpen((o) => new Set([...o, ...r.open]));
          setPinned((p) => new Set([...p, ...r.pinned]));
          setCursor(r.keyOf.get(sel.focus) ?? null);
        }
      }
    }
  }

  // keep the cursor in view while the user moves it with the keys
  useEffect(() => {
    const tree = treeRef.current;
    if (!tree || !tree.contains(document.activeElement)) return;
    document.getElementById(`${base}-i${at}`)?.scrollIntoView?.({ block: "nearest" });
  }, [at, base]);

  function moveTo(i: number) {
    const item = items[Math.max(0, Math.min(items.length - 1, i))];
    if (!item) return;
    setCursor(item.key);
    if (item.kind === "node") sel.setFocus(item.nodeId!);
  }

  function toggle(item: TreeItem, to?: boolean) {
    if (!item.expandable) return;
    const next = to ?? !item.open;
    setOpen((o) => {
      const s = new Set(o);
      if (next) s.add(item.key);
      else s.delete(item.key);
      return s;
    });
  }

  async function loadPage(uid: string, gid: string) {
    const key = `${uid}|${gid}`;
    const offset = pages.get(key)?.offset ?? 0;
    setPages((p) => new Map(p).set(key, { offset, status: "loading" }));
    try {
      const g = parseGid(gid);
      const page = await exploreApi.neighbors({ uid, ...g, offset, limit: SNAPSHOT_PAGE });
      setPages((p) => new Map(p).set(key, { offset: offset + page.items.length, status: "idle" }));
      if (page.graph) onGraph(page.graph);
    } catch (err) {
      setPages((p) => new Map(p).set(key, { offset, status: "error", message: message(err) }));
    }
  }

  function act(item: TreeItem) {
    if (item.kind === "ref" && item.target) {
      const i = indexOf.get(item.target);
      if (i !== undefined) moveTo(i);
    } else if (item.kind === "more" && item.more === "result" && item.parent) {
      const parent = item.parent;
      setLimits((l) => new Map(l).set(parent, (l.get(parent) ?? RESULT_PAGE) + RESULT_PAGE));
    } else if (item.kind === "more" && item.more === "snapshot" && !item.disabled && item.uid && item.group) {
      void loadPage(item.uid, item.group.id);
    } else if (item.kind === "error" && item.retry) {
      if (item.retry.kind === "detail") detailOf.get(item.retry.uid)?.refetch();
      else void loadPage(item.retry.uid, item.retry.gid);
    }
  }

  function copy(index: number) {
    const text = branchText(adj, items, index);
    const lines = text.split("\n").length;
    const done = () => {
      setFallback(null);
      setStatus(`Copied ${lines} line${lines === 1 ? "" : "s"}`);
    };
    const fail = () => {
      setFallback(text);
      setStatus("Clipboard blocked");
    };
    if (!navigator.clipboard?.writeText) return fail();
    navigator.clipboard.writeText(text).then(done, fail);
  }

  function onKeyDown(e: React.KeyboardEvent) {
    if (!current) return;
    const key = e.key;
    const handled = () => e.preventDefault();
    if (key === "ArrowDown" || key === "j") {
      handled();
      moveTo(at + 1);
    } else if (key === "ArrowUp" || key === "k") {
      handled();
      moveTo(at - 1);
    } else if (key === "ArrowRight" || key === "l") {
      handled();
      if (current.kind === "ref" || current.kind === "more" || current.kind === "error") act(current);
      else if (current.expandable && !current.open) toggle(current, true);
      else if (current.open && items[at + 1]?.parent === current.key) moveTo(at + 1);
    } else if (key === "ArrowLeft" || key === "h") {
      handled();
      if (current.open) toggle(current, false);
      else if (current.parent) moveTo(indexOf.get(current.parent) ?? at);
    } else if (key === "Home") {
      handled();
      moveTo(0);
    } else if (key === "End") {
      handled();
      moveTo(items.length - 1);
    } else if (key === "Enter") {
      handled();
      if (current.kind === "node" && current.uid) onOpen(current.uid);
      else act(current);
    } else if (key === " ") {
      handled();
      toggle(current);
    } else if (key === "/") {
      handled();
      filterRef.current?.focus();
    } else if (key === "y") {
      handled();
      copy(at);
    }
  }

  return (
    <div className="rtree">
      <div className="rtree-bar">
        <label className="eyebrow" htmlFor={`${base}-filter`}>Filter</label>
        <input
          id={`${base}-filter`}
          ref={filterRef}
          type="search"
          className="rtree-filter"
          aria-label="Filter"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Escape" || e.key === "Enter") {
              e.preventDefault();
              treeRef.current?.focus();
            }
          }}
        />
        <button
          type="button"
          className="secondary"
          onClick={() => {
            setOpen(new Set());
            setPinned(new Set());
            setCursor(roots[0] !== undefined ? `n:${roots[0]}` : null);
          }}
        >
          Collapse all
        </button>
        <button type="button" className="secondary" disabled={!current} onClick={() => copy(at)}>
          Copy branch
        </button>
        <span className="hint rtree-status" role="status">
          {status}
        </span>
      </div>
      {fallback !== null && (
        <textarea
          className="rtree-fallback"
          readOnly
          aria-label="Branch text"
          rows={Math.min(12, fallback.split("\n").length)}
          value={fallback}
          onFocus={(e) => e.currentTarget.select()}
        />
      )}
      <div
        ref={treeRef}
        className="rtree-items"
        role="tree"
        aria-label="Result tree"
        tabIndex={0}
        aria-activedescendant={current ? `${base}-i${at}` : undefined}
        onKeyDown={onKeyDown}
      >
        {items.map((item, i) => (
          <Item
            key={item.key}
            id={`${base}-i${i}`}
            item={item}
            guide={guides[i]}
            adj={adj}
            active={i === at}
            match={filtered.matches.has(item.key)}
            slotOf={slotOf}
            palette={palette}
            onClick={() => {
              moveTo(i);
              if (item.kind === "ref" || item.kind === "more" || item.kind === "error") act(item);
            }}
            onToggle={() => {
              moveTo(i);
              toggle(item);
            }}
            onOpen={item.kind === "node" && item.uid ? () => onOpen(item.uid!) : undefined}
          />
        ))}
      </div>
      {current && (
        <Detail
          item={current}
          adj={adj}
          graph={graph}
          sel={sel}
          totalRows={rows.length}
          slotOf={slotOf}
          palette={palette}
          onCopy={() => copy(at)}
          onOpen={onOpen}
          objectPanel={objectPanel}
        />
      )}
    </div>
  );
}

function Item({
  id,
  item,
  guide,
  adj,
  active,
  match,
  slotOf,
  palette,
  onClick,
  onToggle,
  onOpen,
}: {
  id: string;
  item: TreeItem;
  guide: string;
  adj: Adjacency;
  active: boolean;
  match: boolean;
  slotOf: (label: string) => number;
  palette: Palette;
  onClick: () => void;
  onToggle: () => void;
  onOpen?: () => void;
}) {
  const node = item.nodeId ? adj.nodes.get(item.nodeId) : undefined;
  const cls = ["rt-item", `rt-${item.kind}`, active ? "rt-active" : "", match ? "rt-match" : ""]
    .filter(Boolean)
    .join(" ");
  return (
    // The tree container holds the focus and the keys (aria-activedescendant),
    // so an item takes a click only.
    // eslint-disable-next-line jsx-a11y/click-events-have-key-events
    <div
      id={id}
      role="treeitem"
      tabIndex={-1}
      aria-level={item.level}
      aria-setsize={item.setsize}
      aria-posinset={item.posinset}
      aria-expanded={item.expandable ? item.open : undefined}
      aria-selected={active}
      className={cls}

      onClick={onClick}
      onDoubleClick={onOpen}
    >
      <span className="rt-guide" aria-hidden="true">{guide}</span>
      <span
        className="rt-tog"
        onClick={(e) => {
          if (!item.expandable) return;
          e.stopPropagation();
          onToggle();
        }}
        aria-hidden="true"
      >
        {item.kind === "node" || item.kind === "group" ? (item.expandable ? (item.open ? "[-]" : "[+]") : "   ") : ""}
      </span>
      {item.kind === "node" && node && (
        <>
          <SlotMark slot={slotOf(primaryLabel(node))} palette={palette} />
          <span className="rt-caption">{captionFull(node)}</span>
          <LabelChip label={primaryLabel(node)} slot={slotOf(primaryLabel(node))} palette={palette} />
          {summary(node) && <span className="rt-summary">{summary(node)}</span>}
          {item.snapshot && <span className="rt-tag">snapshot</span>}
        </>
      )}
      {item.kind === "group" && item.group && (
        <span className="rt-grouptext">
          <span className="rt-type">{item.group.type}</span> {item.group.direction === "out" ? "to" : "from"} {item.group.label ?? "node"}{" "}
          <span className="rt-count">({countText(item.group)})</span>
        </span>
      )}
      {item.kind === "ref" && (
        <span className="rt-ref">
          {node ? captionFull(node) : item.nodeId} <em>{item.reason === "above" ? "already open above" : "jump to its result branch"}</em>
        </span>
      )}
      {item.kind === "more" && <span className={item.disabled ? "rt-more rt-disabled" : "rt-more"}>{itemText(adj, item)}</span>}
      {item.kind === "loading" && <span className="hint">Loading</span>}
      {item.kind === "error" && (
        <span className="rt-error">
          {item.message} <span className="rt-more">Try again</span>
        </span>
      )}
    </div>
  );
}

function Detail({
  item,
  adj,
  sel,
  totalRows,
  slotOf,
  palette,
  onCopy,
  onOpen,
  objectPanel,
}: {
  item: TreeItem;
  adj: Adjacency;
  graph: ResultGraph;
  sel: ResultSelection;
  totalRows: number;
  slotOf: (label: string) => number;
  palette: Palette;
  onCopy: () => void;
  onOpen: (uid: string) => void;
  objectPanel?: (node: { labels: string[]; properties: Record<string, unknown> }) => React.ReactNode;
}) {
  const [internal, setInternal] = useState(false);
  if (item.kind === "group" && item.group) {
    return (
      <section className="rtree-detail" aria-label="Group detail">
        <div className="rtree-detail-main">
          <h3 className="rtree-detail-title">{groupText(item.group)}</h3>
          <p className="hint">
            {item.group.inResult} in the result{item.group.snapshot !== undefined ? `, ${item.group.snapshot} in the snapshot` : ""}
          </p>
        </div>
        <div className="rtree-actions">
          <button type="button" className="secondary" onClick={onCopy}>Copy branch</button>
        </div>
      </section>
    );
  }
  const node = item.kind === "node" || item.kind === "ref" ? adj.nodes.get(item.nodeId!) : undefined;
  if (!node) return null;
  const hits = sel.rowsOf(node.id);
  const selected = hits.length > 0 && sel.picked.size === hits.length && hits.every((r) => sel.picked.has(r));
  const uid = typeof node.properties.uid === "string" ? node.properties.uid : undefined;
  const entries = Object.entries(node.properties);
  const hidden = entries.filter(([k]) => k.startsWith("_")).length;
  const shown = internal ? entries : entries.filter(([k]) => !k.startsWith("_"));
  const label = primaryLabel(node);
  return (
    <section className="rtree-detail" aria-label="Node detail">
      <div className="rtree-detail-main">
        <h3 className="rtree-detail-title">
          {captionFull(node)} <LabelChip label={label} slot={slotOf(label)} palette={palette} /> <span className="hint">layer {layerOf(node)}</span>
        </h3>
        {hits.length > 0 && (
          <div className="rtree-hits">
            <span>
              In {hits.length} of {totalRows} result rows
            </span>
            <button type="button" className="secondary" disabled={selected} onClick={() => sel.pickRows(hits)}>
              {hits.length === 1 ? "Select this row" : "Select these rows"}
            </button>
          </div>
        )}
        <dl className="rtree-props">
          {shown.map(([k, v]) => (
            <div key={k}>
              <dt>{k}</dt>
              <dd>{typeof v === "object" && v !== null ? JSON.stringify(v) : String(v)}</dd>
            </div>
          ))}
        </dl>
        {hidden > 0 && (
          <button type="button" className="linklike" onClick={() => setInternal((v) => !v)}>
            {internal ? "Hide" : "Show"} {hidden} internal properties
          </button>
        )}
        {objectPanel?.({ labels: node.labels, properties: node.properties })}
      </div>
      <div className="rtree-actions">
        {uid && (
          <button type="button" className="secondary" onClick={() => onOpen(uid)}>Open in Search</button>
        )}
        <button type="button" className="secondary" onClick={onCopy}>Copy branch</button>
      </div>
    </section>
  );
}
