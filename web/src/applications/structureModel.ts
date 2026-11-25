import type { ElementDefinition } from "cytoscape";
import type { DagreLayoutOptions } from "cytoscape-dagre";
import type { GraphLayoutOptions } from "../explore/graphElements";
import { resultLabel, type ResultValue } from "../results/text";
import type {
  ApplicationMember,
  BusinessApplicationDefinition,
  FlowCheck,
  ResolvedApplication,
} from "./types";

// The model imports Cytoscape types only.

/** The source a member states: its address, its inventory reference or its placeholder. */
export function memberSource(member: ApplicationMember): string {
  if (member.placeholder)
    return `${member.placeholder.status} placeholder: ${member.placeholder.text}`;
  return member.address ?? `${member.inventory?.kind} ${member.inventory?.uid}`;
}

/** The class and colour key of a flow check answer: passes, fails, not decided (`open`). */
export type EdgeAnswer = "passes" | "fails" | "open";

/** The class and colour key of a flow check result, or null when the connection was not evaluated. */
export function edgeAnswer(result: ResultValue | null | undefined): EdgeAnswer | null {
  if (!result) return null;
  return result.answer === "true" ? "passes" : result.answer === "false" ? "fails" : "open";
}

/** A component group as the graph draws it. */
export interface StructureNode {
  id: string;
  name: string;
  members: number;
  placeholders: number;
}
/** A connection as the graph draws it: the flow check result and its class
 *  key when a flow check evaluated it, and the readiness when a resolution is
 *  known. */
export interface StructureEdge {
  id: string;
  name: string;
  source: string;
  destination: string;
  answer: EdgeAnswer | null;
  result: ResultValue | null;
  readiness: "ready" | "unresolved" | null;
}
export interface StructureGraphModel {
  nodes: StructureNode[];
  edges: StructureEdge[];
}

/** The groups of a definition as nodes and its connections as edges. A
 *  connection whose source or destination names no group is left out. */
export function structureGraph(
  definition: BusinessApplicationDefinition,
  resolution?: ResolvedApplication | null,
  flows?: FlowCheck[] | null,
): StructureGraphModel {
  const nodes = definition.groups.map((group) => ({
    id: group.id,
    name: group.name,
    members: group.members.length,
    placeholders: group.members.filter((member) => member.placeholder).length,
  }));
  const groups = new Set(nodes.map((node) => node.id));
  const readiness = new Map(
    (resolution?.connections ?? []).map((item) => [item.id, item.readiness] as const),
  );
  const results = new Map((flows ?? []).map((flow) => [flow.connection_id, flow.result] as const));
  const edges = definition.connections
    .filter((connection) => groups.has(connection.source) && groups.has(connection.destination))
    .map((connection) => {
      const result = results.get(connection.id) ?? null;
      return {
        id: connection.id,
        name: connection.name,
        source: connection.source,
        destination: connection.destination,
        answer: edgeAnswer(result),
        result,
        readiness: readiness.get(connection.id) ?? null,
      };
    });
  return { nodes, edges };
}

export function countText(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

export function nodeText(node: StructureNode): string {
  return node.placeholders > 0
    ? `${countText(node.members, "member")}, ${countText(node.placeholders, "placeholder")}`
    : countText(node.members, "member");
}

/** The state an edge caption and the text alternative give after the connection name. */
export function edgeState(edge: StructureEdge): string | null {
  if (edge.result) return resultLabel(edge.result);
  return edge.readiness === "unresolved" ? "unresolved" : null;
}

/** A group and a connection can share an id. */
export function structureElements(graph: StructureGraphModel): ElementDefinition[] {
  return [
    ...graph.nodes.map((node) => ({
      group: "nodes" as const,
      data: { id: `group:${node.id}`, caption: `${node.name}\n${nodeText(node)}` },
      classes: node.placeholders > 0 ? "placeholder" : "",
    })),
    ...graph.edges.map((edge) => {
      const state = edgeState(edge);
      return {
        group: "edges" as const,
        data: {
          id: `connection:${edge.id}`,
          source: `group:${edge.source}`,
          target: `group:${edge.destination}`,
          caption: state ? `${edge.name}: ${state}` : edge.name,
        },
        classes: [edge.answer ?? "", edge.readiness === "unresolved" ? "unresolved" : ""]
          .filter(Boolean)
          .join(" "),
      };
    }),
  ];
}

/** The instance options that keep the picture read-only: no node can be
 *  moved, nothing can be selected and there is no box selection. Panning and
 *  zooming stay. */
export const READ_ONLY = {
  autoungrabify: true,
  autounselectify: true,
  boxSelectionEnabled: false,
} as const;

/** Groups in the direction the connections run: left to right, or top to
 *  bottom in a narrow column. */
export function structureLayout(rankDir: "LR" | "TB" = "LR"): GraphLayoutOptions {
  return {
    name: "dagre",
    animate: false,
    fit: true,
    padding: 24,
    nodeDimensionsIncludeLabels: true,
    rankDir,
    nodeSep: 36,
    edgeSep: 12,
    rankSep: rankDir === "TB" ? 60 : 120,
  } satisfies DagreLayoutOptions;
}
