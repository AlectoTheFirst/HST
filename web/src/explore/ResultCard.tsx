/** The owner keys the card on the run. */

import { Suspense, lazy, useCallback, useEffect, useMemo, useState } from "react";
import type { QueryResult, ResultGraph, ResultRow } from "../api/types";
import { useAiContext, useAiPaneId } from "../ai/context";
import { readJson, writeJson } from "../shell/storage";
import { captionFull, growSlots, MAX_GROWN_NODES, mergeGraphs, OTHER_SLOT, slots } from "./graphElements";
import { readPalette, watchTheme } from "./graphStyle";
import { DEFAULT_WIDTH, drawnIds, picture, PICTURE_CAP, type PictureDir } from "./lanes";
import { LanesPanel } from "./LanesPanel";
import { hasRowLinks, useResultSelection } from "./resultSelection";
import { ResultsTable, rowCountText } from "./ResultsTable";
import { ResultTree } from "./ResultTree";
import { adjacency, rootsOf } from "./treeModel";
import "./resultcard.css";

const QueryGraph = lazy(() => import("./QueryGraph"));

export type View = "table" | "tree" | "canvas";
const VIEWS: ReadonlyArray<readonly [View, string]> = [["table", "Table"], ["tree", "Tree"], ["canvas", "Canvas"]];
export const VIEW_KEY = "hst-explore-result-view";
export const PICTURE_KEY = "hst-explore-picture";
export const PICTURE_DIR_KEY = "hst-explore-picture-dir";

const EMPTY_ROWS: ResultRow[] = [];

function storedView(): View {
  const v = readJson<unknown>(VIEW_KEY, "tree");
  return v === "table" || v === "tree" || v === "canvas" ? v : "tree";
}

type ObjectPanel = (node: { labels: string[]; properties: Record<string, unknown> }) => React.ReactNode;

export function ResultCard({ result, onOpen, objectPanel }: {
  result: QueryResult | null;
  onOpen: (uid: string) => void;
  objectPanel?: ObjectPanel;
}) {
  const base = result?.graph;
  if (!result) return <ResultsTable result={result} />;
  // Without graph nodes the table is the only view; the switch shows it.
  if (!base || base.nodes.length === 0)
    return (
      <div className="results result-card">
        <div className="rc-head">
          <span className="eyebrow tabletitle">{rowCountText(result)}</span>
          <span className="rc-spacer" />
          <div className="segs" role="group" aria-label="Result view">
            {VIEWS.map(([v, label]) => (
              <button key={v} type="button" aria-pressed={v === "table"} className={v === "table" ? "on" : ""} disabled={v !== "table"}>
                {label}
              </button>
            ))}
          </div>
        </div>
        {result.truncated && (
          <div className="results-truncated" role="status">
            More than {result.data?.length ?? 0} rows
          </div>
        )}
        <ResultsTable bare result={result} />
      </div>
    );
  return <GraphResult result={result} base={base} onOpen={onOpen} objectPanel={objectPanel} />;
}

function GraphResult({ result, base, onOpen, objectPanel }: {
  result: QueryResult;
  base: ResultGraph;
  onOpen: (uid: string) => void;
  objectPanel?: ObjectPanel;
}) {
  const rows = result.data ?? EMPTY_ROWS;
  const [view, setViewState] = useState<View>(storedView);
  const [showPicture, setShowPicture] = useState<boolean>(() => readJson<boolean>(PICTURE_KEY, true) !== false);
  const [state, setState] = useState(() => ({ graph: base, slots: slots(base) }));
  const [palette, setPalette] = useState(readPalette);
  useEffect(() => watchTheme(() => setPalette(readPalette())), []);

  const setView = (v: View) => {
    setViewState(v);
    writeJson(VIEW_KEY, v);
  };
  const togglePicture = () => {
    setShowPicture((s) => {
      writeJson(PICTURE_KEY, !s);
      return !s;
    });
  };
  const addToGraph = useCallback((payload: ResultGraph) => {
    setState((s) => {
      const graph = mergeGraphs(s.graph, payload);
      return { graph, slots: growSlots(s.slots, graph) };
    });
  }, []);

  const sel = useResultSelection(rows);
  const adj = useMemo(() => adjacency(state.graph), [state.graph]);
  const resultRels = useMemo(() => new Set(base.relationships.map((r) => r.id)), [base]);
  const { roots, rowsOfRoot } = useMemo(() => rootsOf(rows, base), [rows, base]);
  const slotOf = useCallback((label: string) => state.slots.get(label) ?? OTHER_SLOT, [state.slots]);
  const rowLinks = hasRowLinks(rows);

  // The picked rows draw the picture. A focused node that this picture does not
  // show becomes the only seed.
  const rowDrawn = useMemo(() => drawnIds(adj, sel.rowSeeds), [adj, sel.rowSeeds]);
  const fromRows = sel.rowSeeds.length > 0 && (sel.focus === null || rowDrawn.has(sel.focus));
  const seeds = useMemo(() => (fromRows ? sel.rowSeeds : sel.focus !== null ? [sel.focus] : []), [fromRows, sel.rowSeeds, sel.focus]);
  const [openGroups, setOpenGroups] = useState<ReadonlySet<string>>(new Set());
  const toggleGroup = useCallback(
    (id: string) =>
      setOpenGroups((o) => {
        const next = new Set(o);
        if (next.has(id)) next.delete(id);
        else next.add(id);
        return next;
      }),
    [],
  );
  const [pictureDir, setPictureDir] = useState<PictureDir>(() => (readJson<unknown>(PICTURE_DIR_KEY, "tb") === "lr" ? "lr" : "tb"));
  const choosePictureDir = useCallback((dir: PictureDir) => {
    writeJson(PICTURE_DIR_KEY, dir);
    setPictureDir(dir);
  }, []);
  const [pictureWidth, setPictureWidth] = useState(DEFAULT_WIDTH);
  const pic = useMemo(
    () => picture(adj, seeds, slotOf, openGroups, PICTURE_CAP, { dir: pictureDir, width: pictureWidth }),
    [adj, seeds, slotOf, openGroups, pictureDir, pictureWidth],
  );
  const picked = [...sel.picked].sort((a, b) => a - b);
  const focusNode = sel.focus !== null ? adj.nodes.get(sel.focus) : undefined;
  const pictureTitle = fromRows
    ? picked.length <= 3
      ? `Row${picked.length === 1 ? "" : "s"} ${picked.map((r) => r + 1).join(", ")}`
      : `${picked.length} rows`
    : focusNode
      ? `Node ${captionFull(focusNode)}`
      : "";

  // S8: the focused node is the selection the AI pane reads
  const focusUid = sel.focus ? adj.nodes.get(sel.focus)?.properties.uid : undefined;
  useAiContext(
    useAiPaneId(),
    typeof focusUid === "string" && focusUid ? { selection: [{ kind: "graph_node", uid: focusUid, source: "selection" }] } : null,
  );

  const pictureShown = showPicture && view !== "canvas";
  const full = state.graph.nodes.length >= MAX_GROWN_NODES;

  return (
    <div className="results result-card">
      <div className="rc-head">
        <span className="eyebrow tabletitle">{rowCountText(result)}</span>
        {base.truncated && <span className="rc-partial">partial graph</span>}
        <span className="rc-spacer" />
        {view === "table" && sel.picked.size > 0 && (
          <button type="button" className="secondary rc-small" onClick={() => setView("tree")}>Show in tree</button>
        )}
        {view !== "canvas" && (
          <button type="button" className="secondary rc-small" aria-pressed={showPicture} onClick={togglePicture}>Picture</button>
        )}
        <div className="segs" role="group" aria-label="Result view">
          {VIEWS.map(([v, label]) => (
            <button key={v} type="button" aria-pressed={view === v} className={view === v ? "on" : ""} onClick={() => setView(v)}>
              {label}
            </button>
          ))}
        </div>
      </div>
      {result.truncated && (
        <div className="results-truncated" role="status">
          More than {rows.length} rows
        </div>
      )}
      <div className={pictureShown ? "rc-body rc-with-picture" : "rc-body"}>
        <div className="rc-view">
          {view === "table" && (
            <ResultsTable bare result={result} picked={sel.picked} hits={sel.hits} onPick={rowLinks ? sel.onPick : undefined} />
          )}
          {view === "tree" && (
            <ResultTree
              rows={rows}
              graph={state.graph}
              adj={adj}
              roots={roots}
              rowsOfRoot={rowsOfRoot}
              resultRels={resultRels}
              sel={sel}
              full={full}
              slotOf={slotOf}
              palette={palette}
              onGraph={addToGraph}
              onOpen={onOpen}
              objectPanel={objectPanel}
            />
          )}
          {view === "canvas" && (
            <Suspense fallback={<div className="hint">Loading</div>}>
              <QueryGraph graph={state.graph} onGraph={addToGraph} onOpen={onOpen} objectPanel={objectPanel} />
            </Suspense>
          )}
        </div>
        {pictureShown && (
          <LanesPanel
            pic={pic}
            nodes={adj.nodes}
            focus={sel.focus}
            title={pictureTitle}
            palette={palette}
            onDir={choosePictureDir}
            onWidth={setPictureWidth}
            onToggleGroup={toggleGroup}
            onFocus={sel.setFocus}
            onOpen={onOpen}
          />
        )}
      </div>
    </div>
  );
}
