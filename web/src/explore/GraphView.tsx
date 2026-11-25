/** With `grows`, a graph that keeps every drawn node is added to the live instance. */

import type cytoscape from "cytoscape";
import { withLayouts } from "../graph/cytoscape";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import type { GraphNode, ResultGraph } from "../api/types";
import { readJson, writeJson } from "../shell/storage";
import {
  DEFAULT_LAYOUT,
  LAYOUTS,
  MAX_ZOOM,
  MIN_ZOOM,
  captionFull,
  extendsDrawn,
  growSlots,
  growthLayoutOptions,
  layoutOptions,
  legend,
  primaryLabel,
  seedPositions,
  slots,
  toElements,
  type LayoutName,
  type Point,
} from "./graphElements";
import { FADED, readPalette, slotColor, stylesheet, watchTheme } from "./graphStyle";
import "./graphview.css";

const ZOOM_STEP = 1.4;
/** Padding, in model units, between the outermost node and the viewport edge. */
const FIT_PAD = 28;

const HEIGHT_KEY = "hst-graph-height";
const DEFAULT_HEIGHT = 520;
const MIN_HEIGHT = 240;
const MAX_HEIGHT = 2000;

function clampHeight(value: unknown): number {
  const n = typeof value === "number" && Number.isFinite(value) ? value : DEFAULT_HEIGHT;
  return Math.min(MAX_HEIGHT, Math.max(MIN_HEIGHT, Math.round(n)));
}

export default function GraphView({ graph, onOpen, grows = false, selectedPanel }: {
  graph: ResultGraph;
  /** Only a node with a uid can be opened. */
  onOpen?: (uid: string) => void;
  /** Add to the drawn picture when the graph only gains nodes. */
  grows?: boolean;
  /** More content for the selected node's panel, above its properties. */
  selectedPanel?: (node: GraphNode) => ReactNode;
}) {
  const host = useRef<HTMLDivElement | null>(null);
  const cy = useRef<cytoscape.Core | null>(null);
  /** The layout the live instance was placed with. */
  const placed = useRef<LayoutName | null>(null);

  const [layout, setLayout] = useState<LayoutName>(DEFAULT_LAYOUT);
  const [zoom, setZoom] = useState(1);
  const [selected, setSelected] = useState<string | null>(null);
  const selectedRef = useRef<string | null>(null);
  const openRef = useRef(onOpen);
  const byIdRef = useRef<Map<string, GraphNode>>(new Map());
  const [full, setFull] = useState(false);
  const [height, setHeight] = useState(() => clampHeight(readJson<number>(HEIGHT_KEY, DEFAULT_HEIGHT)));
  const [palette, setPalette] = useState(() => readPalette());

  const byId = useMemo(() => new Map(graph.nodes.map((n) => [n.id, n])), [graph]);
  useEffect(() => {
    openRef.current = onOpen;
    byIdRef.current = byId;
  }, [onOpen, byId]);
  // A growth keeps the slot of every label already drawn.
  const [slotState, setSlotState] = useState(() => ({ graph, map: slots(graph) }));
  let slotMap = slotState.map;
  if (slotState.graph !== graph) {
    const keep = grows && extendsDrawn(new Set(slotState.graph.nodes.map((n) => n.id)), graph);
    slotMap = keep ? growSlots(slotState.map, graph) : slots(graph);
    setSlotState({ graph, map: slotMap });
  }
  const key = useMemo(() => legend(graph, slotMap), [graph, slotMap]);
  const drawn = useMemo(
    () => graph.relationships.filter((r) => byId.has(r.start) && byId.has(r.end)),
    [graph, byId],
  );

  const focusNode = useCallback((id: string | null) => {
    setSelected(id);
    selectedRef.current = id;
    const core = cy.current;
    if (!core) return;
    core.batch(() => {
      core.elements().unselect().removeClass(FADED);
      if (id === null) return;
      const node = core.$id(id);
      if (node.empty()) return;
      node.select();
      core.elements().difference(node.closedNeighborhood()).addClass(FADED);
    });
  }, []);

  // The node list of the text alternative is one tab stop with roving focus.
  const listRef = useRef<HTMLUListElement | null>(null);
  const [cursor, setCursor] = useState(0);
  const moveCursor = useCallback(
    (e: React.KeyboardEvent<HTMLButtonElement>, index: number) => {
      const last = graph.nodes.length - 1;
      const next =
        e.key === "ArrowDown" || e.key === "ArrowRight"
          ? Math.min(last, index + 1)
          : e.key === "ArrowUp" || e.key === "ArrowLeft"
            ? Math.max(0, index - 1)
            : e.key === "Home"
              ? 0
              : e.key === "End"
                ? last
                : null;
      if (next === null) return;
      e.preventDefault();
      setCursor(next);
      listRef.current?.querySelector<HTMLButtonElement>(`[data-node-index="${next}"]`)?.focus();
    },
    [graph.nodes.length],
  );
  /** A node picked from the list is selected, and the canvas centres on it
   *  when it is outside the viewport. */
  const pickFromList = useCallback(
    (id: string) => {
      focusNode(id);
      const core = cy.current;
      const node = core?.$id(id);
      if (!core || !node || node.empty()) return;
      const box = node.renderedBoundingBox();
      if (box.x1 < 0 || box.y1 < 0 || box.x2 > core.width() || box.y2 > core.height()) core.center(node);
    },
    [focusNode],
  );

  const runLayout = useCallback((core: cytoscape.Core, name: LayoutName, nodeCount: number) => {
    // cytoscape's `LayoutOptions` union types the built-in layouts only.
    core.layout(layoutOptions(name, nodeCount) as cytoscape.LayoutOptions).run();
  }, []);

  useEffect(() => {
    const container = host.current;
    const live = cy.current;
    if (grows && container && live && extendsDrawn(new Set(live.nodes().map((n) => n.id())), graph)) {
      const fixed = new Map<string, Point>(live.nodes().map((n) => [n.id(), { ...n.position() }]));
      const seeds = seedPositions(graph, fixed);
      live.batch(() => {
        for (const element of toElements(graph, slotMap)) {
          const id = element.data.id!;
          const drawn = live.getElementById(id);
          if (drawn.empty()) {
            live.add(element.group === "nodes" ? { ...element, position: seeds.get(id) } : element);
          }
        }
      });
      if (seeds.size > 0) {
        const name = placed.current ?? layout;
        if (name === "fcose") {
          const added = live.nodes().filter((n) => seeds.has(n.id()));
          const eles = added.union(added.neighborhood());
          const held = new Map([...fixed].filter(([id]) => eles.getElementById(id).nonempty()));
          eles.layout(growthLayoutOptions(name, eles.nodes().length, held) as cytoscape.LayoutOptions).run();
          const [anchorId, anchorAt] = [...held][0] ?? [];
          if (anchorId && anchorAt) {
            const now = live.getElementById(anchorId).position();
            const dx = anchorAt.x - now.x;
            const dy = anchorAt.y - now.y;
            if (dx !== 0 || dy !== 0) eles.nodes().shift({ x: dx, y: dy });
          }
          const view = live.extent();
          const box = added.boundingBox();
          if (box.x1 < view.x1 || box.y1 < view.y1 || box.x2 > view.x2 || box.y2 > view.y2) {
            live.fit(eles, FIT_PAD);
          }
        } else {
          live.layout(growthLayoutOptions(name, graph.nodes.length, fixed) as cytoscape.LayoutOptions).run();
        }
        setZoom(live.zoom());
      }
      focusNode(selectedRef.current);
      return;
    }
    live?.destroy();
    cy.current = null;
    placed.current = null;
    if (!container || graph.nodes.length === 0) return;
    const core = withLayouts()({
      container,
      elements: toElements(graph, slotMap),
      // the elements hold their start positions
      layout: { name: "preset" },
      style: stylesheet(palette),
      minZoom: MIN_ZOOM,
      maxZoom: MAX_ZOOM,
      boxSelectionEnabled: false,
      selectionType: "single",
      // a cached bitmap while panning
      textureOnViewport: graph.nodes.length > 150,
    });
    cy.current = core;

    const sync = () => setZoom(core.zoom());
    core.on("zoom", sync);
    core.on("tap", "node", (event) => focusNode(event.target.id()));
    core.on("dbltap", "node", (event) => {
      const uid = byIdRef.current.get(event.target.id())?.properties.uid;
      if (typeof uid === "string") openRef.current?.(uid);
    });
    core.on("tap", (event) => {
      if (event.target === core) focusNode(null);
    });
    placed.current = layout;
    runLayout(core, layout, graph.nodes.length);
    sync();
    // The effects below re-place or restyle this instance on a change of
    // `layout` or `palette`.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph, slotMap, focusNode, runLayout]);

  useEffect(
    () => () => {
      cy.current?.destroy();
      cy.current = null;
      placed.current = null;
    },
    [],
  );

  useEffect(() => watchTheme(() => setPalette(readPalette())), []);

  useEffect(() => {
    cy.current?.style(stylesheet(palette));
  }, [palette]);

  useEffect(() => {
    const core = cy.current;
    if (!core || placed.current === layout) return;
    placed.current = layout;
    focusNode(null);
    runLayout(core, layout, graph.nodes.length);
  }, [layout, graph, focusNode, runLayout]);

  // Only a height set by a pointer drag outside full screen is stored.
  const fullRef = useRef(full);
  useEffect(() => {
    fullRef.current = full;
  }, [full]);
  useEffect(() => {
    const container = host.current?.parentElement;
    if (!container || typeof ResizeObserver === "undefined") return;
    let dragging = false;
    let moved: number | null = null;
    const first = container.getBoundingClientRect();
    let empty = first.width === 0 || first.height === 0;
    const observer = new ResizeObserver(() => {
      cy.current?.resize();
      const rect = container.getBoundingClientRect();
      const nowEmpty = rect.width === 0 || rect.height === 0;
      if (empty && !nowEmpty && cy.current) {
        cy.current.fit(undefined, FIT_PAD);
        setZoom(cy.current.zoom());
      }
      empty = nowEmpty;
      if ((rect.width === 0 && rect.height === 0) || fullRef.current || !dragging) return;
      moved = clampHeight(rect.height);
    });
    const down = () => {
      dragging = true;
      moved = null;
    };
    const up = () => {
      if (dragging && moved !== null) {
        setHeight(moved);
        writeJson(HEIGHT_KEY, moved);
      }
      dragging = false;
    };
    container.addEventListener("pointerdown", down);
    window.addEventListener("pointerup", up);
    observer.observe(container);
    return () => {
      container.removeEventListener("pointerdown", down);
      window.removeEventListener("pointerup", up);
      observer.disconnect();
    };
  }, []);

  // Full screen is the `gv-full` class on the pane.
  useEffect(() => {
    const core = cy.current;
    if (!core) return;
    core.resize();
    core.fit(undefined, FIT_PAD);
  }, [full]);

  useEffect(() => {
    if (!full) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setFull(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [full]);

  const zoomBy = useCallback((factor: number) => {
    const core = cy.current;
    if (!core) return;
    core.zoom({
      level: core.zoom() * factor,
      renderedPosition: { x: core.width() / 2, y: core.height() / 2 },
    });
  }, []);

  const fit = useCallback(() => cy.current?.fit(undefined, FIT_PAD), []);

  if (graph.nodes.length === 0) return null;

  const chosen: GraphNode | undefined = selected ? byId.get(selected) : undefined;

  return (
    <div className={"graphview" + (full ? " gv-full" : "")}>
      <div className="graphview-head">
        <span className="eyebrow">Graph</span>
        <span className="hint">
          {graph.nodes.length} node{graph.nodes.length === 1 ? "" : "s"},{" "}
          {graph.relationships.length} relationship
          {graph.relationships.length === 1 ? "" : "s"}
          {graph.truncated && ", partial"}
        </span>
      </div>

      <div className="gv-controls">
        <label className="gv-layout">
          <span className="eyebrow">Layout</span>
          <select
            value={layout}
            onChange={(e) => setLayout(e.target.value as LayoutName)}
            aria-label="Layout"
          >
            {LAYOUTS.map((option) => (
              <option key={option.name} value={option.name}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <button type="button" onClick={() => zoomBy(1 / ZOOM_STEP)} aria-label="Zoom out">
          &minus;
        </button>
        <span className="rb-zoomlevel">{Math.round(zoom * 100)}%</span>
        <button type="button" onClick={() => zoomBy(ZOOM_STEP)} aria-label="Zoom in">
          +
        </button>
        <button type="button" onClick={fit}>
          Fit
        </button>
        <button
          type="button"
          onClick={() => setFull((on) => !on)}
        >
          {full ? "Exit full screen" : "Full screen"}
        </button>
      </div>

      <div className="gv-stage" style={full ? undefined : { height }}>
        <div
          ref={host}
          className="graphview-canvas"
          role="img"
          aria-label={`Graph of ${graph.nodes.length} nodes and ${graph.relationships.length} relationships`}
        />
      </div>

      {key.length > 1 && (
        <ul className="gv-legend">
          {key.map((entry) => (
            <li key={entry.kind}>
              <span
                className={`gv-swatch gv-slot${entry.slot}`}
                style={{ background: slotColor(palette, entry.slot) }}
              />
              {entry.kind}
              <span className="gv-count">{entry.count}</span>
            </li>
          ))}
        </ul>
      )}

      <ul className="gv-sr" aria-label="Nodes and relationships" ref={listRef}>
        {graph.nodes.map((node, index) => (
          <li key={node.id}>
            {/* one tab stop for the whole list with roving focus */}
            <button
              type="button"
              data-node-index={index}
              tabIndex={index === Math.min(cursor, graph.nodes.length - 1) ? 0 : -1}
              onClick={() => {
                setCursor(index);
                pickFromList(node.id);
              }}
              onKeyDown={(e) => moveCursor(e, index)}
            >
              {primaryLabel(node)} {captionFull(node)}
            </button>
          </li>
        ))}
        {drawn.map((rel) => (
          <li key={rel.id}>
            {captionFull(byId.get(rel.start)!)} <span>{rel.type}</span>{" "}
            {captionFull(byId.get(rel.end)!)}
          </li>
        ))}
      </ul>

      {chosen && onOpen && typeof chosen.properties.uid === "string" && (
        <div className="gv-open">
          <button type="button" className="secondary" onClick={() => onOpen(chosen.properties.uid as string)}>
            Open {captionFull(chosen)}
          </button>
        </div>
      )}
      {chosen && selectedPanel?.(chosen)}
      {chosen && (
        <dl className="graphview-props">
          <dt>Labels</dt>
          <dd>{chosen.labels.join(", ") || "no labels"}</dd>
          {Object.entries(chosen.properties).map(([name, value]) => (
            <div className="gv-prop" key={name}>
              <dt>{name}</dt>
              <dd>{typeof value === "object" ? JSON.stringify(value) : String(value)}</dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}
