import type cytoscape from "cytoscape";
import type { Css, StylesheetJson } from "cytoscape";
import { useEffect, useRef, useState } from "react";
import { readPalette, slotColor, watchTheme, type Palette } from "../explore/graphStyle";
import { withLayouts } from "../graph/cytoscape";
import {
  READ_ONLY,
  edgeState,
  nodeText,
  structureElements,
  structureLayout,
  type EdgeAnswer,
  type StructureGraphModel,
} from "./structureModel";
import "../explore/graphview.css";

// MIN_ZOOM depends on Cytoscape hiding captions below MIN_ZOOMED_FONT_SIZE.
export const MIN_ZOOM = 0.1;
export const MIN_ZOOMED_FONT_SIZE = 6;

const FONT = 'Archivo, system-ui, -apple-system, "Segoe UI", Arial, sans-serif';
// the categorical slots of the Explore palette (graphStyle.ts): green, red, yellow
const ANSWER_SLOT: Record<EdgeAnswer, number> = { passes: 5, fails: 7, open: 3 };

function structureStyle(palette: Palette): StylesheetJson {
  const node: Css.Node = {
    shape: "round-rectangle",
    width: 170,
    height: 56,
    "background-color": palette.panel2,
    "border-width": 2,
    "border-style": "solid",
    "border-color": palette.line,
    label: "data(caption)",
    "text-wrap": "wrap",
    "text-max-width": "160px",
    "text-valign": "center",
    "text-halign": "center",
    "font-family": FONT,
    "font-size": 12,
    "min-zoomed-font-size": MIN_ZOOMED_FONT_SIZE,
    color: palette.text,
  };
  const edge: Css.Edge = {
    width: 2,
    "curve-style": "bezier",
    "line-color": palette.line,
    "target-arrow-shape": "triangle",
    "target-arrow-color": palette.line,
    label: "data(caption)",
    "font-family": FONT,
    "font-size": 11,
    "min-zoomed-font-size": MIN_ZOOMED_FONT_SIZE,
    color: palette.muted2,
    "text-rotation": "autorotate",
    "text-background-color": palette.panel,
    "text-background-opacity": 0.85,
    "text-background-padding": "2px",
  };
  const answers = (Object.keys(ANSWER_SLOT) as Array<keyof typeof ANSWER_SLOT>).map((answer) => {
    const colour = slotColor(palette, ANSWER_SLOT[answer]);
    return { selector: `edge.${answer}`, style: { "line-color": colour, "target-arrow-color": colour, width: 3 } as Css.Edge };
  });
  return [
    { selector: "node", style: node },
    { selector: "node.placeholder", style: { "border-style": "dashed", "border-color": palette.muted } as Css.Node },
    { selector: "edge", style: edge },
    ...answers,
    { selector: "edge.unresolved", style: { "line-style": "dashed" } as Css.Edge },
  ];
}

const FIT_PAD = 24;

/** The dependency graph of a definition has one node per component group and one edge per connection. */
export default function StructureGraph({ graph }: { graph: StructureGraphModel }) {
  const host = useRef<HTMLDivElement | null>(null);
  const cy = useRef<cytoscape.Core | null>(null);
  const [palette, setPalette] = useState(() => readPalette());
  useEffect(() => watchTheme(() => setPalette(readPalette())), []);

  useEffect(() => {
    const container = host.current;
    if (!container || graph.nodes.length === 0) return;
    const core = withLayouts()({
      container,
      elements: structureElements(graph),
      style: structureStyle(palette),
      minZoom: MIN_ZOOM,
      maxZoom: 4,
      ...READ_ONLY,
    });
    const narrow = container.clientWidth > 0 && container.clientWidth < container.clientHeight * 1.2;
    core.layout(structureLayout(narrow ? "TB" : "LR") as cytoscape.LayoutOptions).run();
    cy.current = core;
    return () => {
      core.destroy();
      cy.current = null;
    };
  }, [graph, palette]);

  if (graph.nodes.length === 0) return <p>No groups</p>;
  const names = new Map(graph.nodes.map((node) => [node.id, node.name]));
  return <div className="application-structure-graph">
    <div className="application-structure-graph-head">
      <button type="button" onClick={() => cy.current?.fit(undefined, FIT_PAD)}>Fit</button>
    </div>
    <div ref={host} className="application-structure-canvas" role="img" aria-label="Dependency graph" />
    <ul className="gv-sr" aria-label="Groups and connections">
      {graph.nodes.map((node) => <li key={`group:${node.id}`}>Group {node.name}: {nodeText(node)}</li>)}
      {graph.edges.map((edge) => {
        const state = edgeState(edge);
        return <li key={`connection:${edge.id}`}>Connection {edge.name}: {names.get(edge.source)} to {names.get(edge.destination)}{state ? `, ${state}` : ""}</li>;
      })}
    </ul>
  </div>;
}
