/**
 * The picture of an evidence chain (ai/chain.ts): statements, tool steps,
 * supporting records and objects in four columns from left to right, laid
 * out by dagre. Loaded lazily by the evidence pane (ai/EvidencePane.tsx).
 *
 * The canvas is hidden from assistive technology: the pane writes the same
 * chain out as a list of buttons, which is also the keyboard's way to a node.
 * A click on a node opens it in the pane. The picture keeps one Cytoscape
 * instance and applies each new chain to it. The colours come from the theme
 * (explore/graphStyle.ts reads them off `<html>`) and follow a theme change.
 */

import { useEffect, useRef, useState } from "react";
import type { Core, ElementDefinition, StylesheetJson } from "cytoscape";
import { withLayouts } from "../graph/cytoscape";
import { readPalette, watchTheme, type Palette } from "../explore/graphStyle";
import type { ChainNode, EvidenceChain } from "./chain";

const FONT = 'Archivo, system-ui, -apple-system, "Segoe UI", Arial, sans-serif';

function style(palette: Palette): StylesheetJson {
  return [
    {
      selector: "node",
      style: {
        shape: "round-rectangle",
        width: 150,
        height: 34,
        "background-color": palette.panel2,
        "border-width": 1,
        "border-color": palette.border,
        label: "data(caption)",
        "text-wrap": "ellipsis",
        "text-max-width": "140px",
        "text-valign": "center",
        "text-halign": "center",
        "font-family": FONT,
        "font-size": 10,
        color: palette.text,
      },
    },
    { selector: "node[kind = 'statement']", style: { "border-color": palette.accent, "border-width": 2 } },
    { selector: "node[kind = 'record']", style: { "border-style": "dashed" } },
    { selector: "node[kind = 'object']", style: { shape: "ellipse", width: 120 } },
    { selector: "node.selected", style: { "border-color": palette.accent, "border-width": 3 } },
    {
      selector: "edge",
      style: {
        width: 1,
        "line-color": palette.line,
        "target-arrow-color": palette.line,
        "target-arrow-shape": "triangle",
        "curve-style": "bezier",
      },
    },
    {
      selector: "edge[kind = 'builds-on']",
      style: {
        "line-style": "dashed",
        "line-color": palette.accent,
        "target-arrow-color": palette.accent,
        label: "data(value)",
        "font-size": 9,
        "font-family": FONT,
        color: palette.muted2,
        "text-background-color": palette.panel,
        "text-background-opacity": 1,
      },
    },
  ];
}

function elements(chain: EvidenceChain): ElementDefinition[] {
  return [
    ...chain.nodes.map((node) => ({ data: { id: node.id, caption: node.label, kind: node.kind } })),
    ...chain.edges.map((edge) => ({
      data: { id: edge.id, source: edge.source, target: edge.target, kind: edge.kind, value: edge.value ?? "" },
    })),
  ];
}

/** Whether the reader asks for reduced motion; true where it cannot be read. */
function reducedMotion(): boolean {
  return typeof window.matchMedia !== "function" || window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

export default function ChainGraph({
  chain,
  selected,
  onOpen,
  large = false,
}: {
  chain: EvidenceChain;
  /** The id of the node the pane shows. */
  selected?: string;
  onOpen: (node: ChainNode) => void;
  /** The size of the enlarge dialog, not of the pane. */
  large?: boolean;
}) {
  const host = useRef<HTMLDivElement | null>(null);
  const cy = useRef<Core | null>(null);
  const [palette, setPalette] = useState(readPalette);
  const openRef = useRef(onOpen);
  useEffect(() => {
    openRef.current = onOpen;
  }, [onOpen]);

  const byId = useRef(new Map<string, ChainNode>());
  const layout = useRef<cytoscape.Layouts | null>(null);

  useEffect(() => {
    const container = host.current;
    if (!container) return;
    const core = withLayouts()({
      container,
      style: style(readPalette()),
      boxSelectionEnabled: false,
      autoungrabify: true,
      minZoom: 0.3,
      maxZoom: 2,
    });
    core.on("tap", "node", (event) => {
      const node = byId.current.get(event.target.id());
      if (node) openRef.current(node);
    });
    cy.current = core;
    return () => {
      layout.current?.stop();
      layout.current = null;
      core.destroy();
      cy.current = null;
    };
  }, []);

  // a new chain adds the elements it gains and removes the ones it lost; dagre
  // then lays the whole chain out again, and the kept nodes move to their new
  // places, animated unless the reader asks for reduced motion
  useEffect(() => {
    const core = cy.current;
    if (!core) return;
    byId.current = new Map(chain.nodes.map((node) => [node.id, node]));
    const next = elements(chain);
    const ids = new Set(next.map((element) => element.data.id!));
    const kept = core.elements().filter((element) => ids.has(element.id())).length;
    core.batch(() => {
      core.elements().filter((element) => !ids.has(element.id())).remove();
      for (const element of next) {
        const existing = core.getElementById(element.data.id!);
        // data() leaves the id and an edge's ends as they are
        if (existing.empty()) core.add(element);
        else existing.data(element.data);
      }
    });
    layout.current?.stop();
    layout.current = core.layout({
      name: "dagre",
      rankDir: "LR",
      nodeSep: 12,
      rankSep: 48,
      animate: kept > 0 && !reducedMotion(),
      animationDuration: 200,
    } as cytoscape.LayoutOptions);
    layout.current.run();
  }, [chain]);

  useEffect(() => {
    const core = cy.current;
    if (!core) return;
    core.nodes().removeClass("selected");
    if (selected) core.getElementById(selected).addClass("selected");
  }, [selected, chain]);

  useEffect(() => watchTheme(() => setPalette(readPalette())), []);
  useEffect(() => {
    cy.current?.style(style(palette));
  }, [palette]);

  useEffect(() => {
    const container = host.current;
    if (!container || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(() => {
      cy.current?.resize();
      cy.current?.fit(undefined, 12);
    });
    observer.observe(container);
    return () => observer.disconnect();
  }, []);

  return <div ref={host} className={"chain-graph" + (large ? " large" : "")} aria-hidden="true" />;
}
