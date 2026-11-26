import type cytoscape from "cytoscape";
import type { Css, ElementDefinition, StylesheetJson } from "cytoscape";
import { useEffect, useRef, useState } from "react";
import { readPalette, watchTheme, type Palette } from "../../explore/graphStyle";
import { withLayouts } from "../../graph/cytoscape";
import { countText, structureLayout } from "../structureModel";
import type { BusinessApplicationDefinition } from "../types";
import { groupName, portText } from "./connectionText";
import "../../explore/graphview.css";

const FONT = 'Archivo, system-ui, -apple-system, "Segoe UI", Arial, sans-serif';
const FIT_PAD = 24;

function graphStyle(palette: Palette): StylesheetJson {
  const node: Css.Node = {
    shape: "round-rectangle",
    width: 170,
    height: 56,
    "background-color": palette.panel2,
    "border-width": 2,
    "border-color": palette.line,
    label: "data(caption)",
    "text-wrap": "wrap",
    "text-max-width": "160px",
    "text-valign": "center",
    "text-halign": "center",
    "font-family": FONT,
    "font-size": 12,
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
    color: palette.muted2,
    "text-background-color": palette.panel,
    "text-background-opacity": 0.85,
    "text-background-padding": "2px",
  };
  return [
    { selector: "node", style: node },
    { selector: "node.on", style: { "border-color": palette.accent, "border-width": 3 } as Css.Node },
    { selector: "edge", style: edge },
  ];
}

/** Groups as boxes and connections as lines with their ports. */
export function componentElements(
  definition: BusinessApplicationDefinition,
  selected: string | null,
): ElementDefinition[] {
  const groups = new Set(definition.groups.map((group) => group.id));
  return [
    ...definition.groups.map((group) => ({
      group: "nodes" as const,
      data: { id: `group:${group.id}`, caption: `${group.name}\n${countText(group.members.length, "member")}` },
      classes: group.id === selected ? "on" : "",
    })),
    ...definition.connections
      .filter((connection) => groups.has(connection.source) && groups.has(connection.destination))
      .map((connection) => ({
        group: "edges" as const,
        data: {
          id: `connection:${connection.id}`,
          source: `group:${connection.source}`,
          target: `group:${connection.destination}`,
          caption: portText(connection),
        },
      })),
  ];
}

/** A click on a box selects its group. Nodes cannot be moved. */
export default function ComponentGraph({
  definition,
  selected,
  onSelect,
}: {
  definition: BusinessApplicationDefinition;
  selected: string | null;
  onSelect: (groupId: string) => void;
}) {
  const host = useRef<HTMLDivElement | null>(null);
  const cy = useRef<cytoscape.Core | null>(null);
  const select = useRef(onSelect);
  const shown = useRef(selected);
  const [palette, setPalette] = useState(() => readPalette());
  useEffect(() => watchTheme(() => setPalette(readPalette())), []);
  useEffect(() => {
    select.current = onSelect;
    shown.current = selected;
  });

  const elements = JSON.stringify(componentElements(definition, null));

  useEffect(() => {
    const container = host.current;
    if (!container || elements === "[]") return;
    const core = withLayouts()({
      container,
      elements: (JSON.parse(elements) as ElementDefinition[]).map((element) =>
        element.data.id === `group:${shown.current}` ? { ...element, classes: "on" } : element,
      ),
      style: graphStyle(palette),
      minZoom: 0.1,
      maxZoom: 4,
      autoungrabify: true,
      autounselectify: true,
      boxSelectionEnabled: false,
    });
    core.layout(structureLayout("LR") as cytoscape.LayoutOptions).run();
    core.on("tap", "node", (event) => select.current(String(event.target.id()).slice("group:".length)));
    cy.current = core;
    return () => {
      core.destroy();
      cy.current = null;
    };
  }, [elements, palette]);

  useEffect(() => {
    const core = cy.current;
    if (!core) return;
    core.nodes().removeClass("on");
    if (selected) core.$id(`group:${selected}`).addClass("on");
  }, [selected]);

  if (definition.groups.length === 0) return <p>No components</p>;
  return (
    <div className="apps-graph">
      <div className="application-structure-graph-head">
        <button type="button" className="secondary" onClick={() => cy.current?.fit(undefined, FIT_PAD)}>
          Fit
        </button>
      </div>
      <div ref={host} className="application-structure-canvas" role="img" aria-label="Component graph" />
      <ul className="gv-sr" aria-label="Components and connections">
        {definition.connections.map((connection) => (
          <li key={connection.id}>
            {groupName(definition, connection.source)} to {groupName(definition, connection.destination)} {portText(connection)}
          </li>
        ))}
      </ul>
    </div>
  );
}
