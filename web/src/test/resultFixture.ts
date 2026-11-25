/**
 * A small query result with a row node index, for the result views tests
 * (treeModel, lanes, resultSelection, ResultCard).
 *
 *   r1 -HAS_INTERFACE-> ge-0/0/1 -HAS_IP-> 10.0.0.1 -IN-> 10.0.0.0/31
 *   r2 -HAS_INTERFACE-> ge-0/0/1 -HAS_IP-> 10.0.0.2 -IN-> 10.0.0.0/31
 *   r1, r2 -LOCATED_IN-> ams
 *
 * Both interfaces have the caption `ge-0/0/1`, for the owner line of the picture.
 */

import type { GraphNode, GraphRelationship, QueryResult, ResultGraph } from "../api/types";

const node = (id: string, labels: string[], properties: Record<string, unknown>): GraphNode => ({ id, labels, properties });
const rel = (id: string, type: string, start: string, end: string): GraphRelationship => ({ id, type, start, end, properties: {} });

export const NODES = {
  d1: node("d1", ["Device", "Obj", "Phys"], { uid: "dev:r1", hostname: "r1", vendor: "Juniper", model: "MX204", role: "router" }),
  d2: node("d2", ["Device", "Obj", "Phys"], { uid: "dev:r2", hostname: "r2" }),
  i1: node("i1", ["Interface", "L2", "Obj"], { uid: "dev:r1/if/ge-0/0/1", name: "ge-0/0/1", kind: "phys", mtu: 9192 }),
  i2: node("i2", ["Interface", "L2", "Obj"], { uid: "dev:r2/if/ge-0/0/1", name: "ge-0/0/1", kind: "phys" }),
  a1: node("a1", ["IpAddress", "L3", "Obj"], { uid: "ip:1", ip: "10.0.0.1" }),
  a2: node("a2", ["IpAddress", "L3", "Obj"], { uid: "ip:2", ip: "10.0.0.2" }),
  p1: node("p1", ["Prefix", "L3", "Obj"], { uid: "pfx:1", cidr: "10.0.0.0/31", kind: "connected" }),
  s1: node("s1", ["Site", "Phys"], { uid: "site:ams", name: "ams", code: "AMS" }),
};

export const RELS = [
  rel("r1", "HAS_INTERFACE", "d1", "i1"),
  rel("r2", "HAS_INTERFACE", "d2", "i2"),
  rel("r3", "HAS_IP", "i1", "a1"),
  rel("r4", "HAS_IP", "i2", "a2"),
  rel("r5", "IN", "a1", "p1"),
  rel("r6", "IN", "a2", "p1"),
  rel("r7", "LOCATED_IN", "d1", "s1"),
  rel("r8", "LOCATED_IN", "d2", "s1"),
];

export const GRAPH: ResultGraph = { nodes: Object.values(NODES), relationships: RELS, truncated: false };

export const RESULT: QueryResult = {
  columns: ["device", "interface", "address"],
  data: [
    { row: ["r1", "ge-0/0/1", "10.0.0.1"], nodes: ["d1", "i1", "a1", "p1", "s1"] },
    { row: ["r2", "ge-0/0/1", "10.0.0.2"], nodes: ["d2", "i2", "a2", "p1", "s1"] },
  ],
  truncated: false,
  graph: GRAPH,
};

/** A hub with `n` interfaces, for the page limit and size tests. */
export function hub(n: number): ResultGraph {
  const nodes = [node("h", ["Device", "Phys"], { uid: "dev:hub", hostname: "hub" })];
  const relationships: GraphRelationship[] = [];
  for (let i = 0; i < n; i++) {
    nodes.push(node(`h${i}`, ["Interface", "L2"], { name: `eth${i}` }));
    relationships.push(rel(`hr${i}`, "HAS_INTERFACE", "h", `h${i}`));
  }
  return { nodes, relationships, truncated: false };
}
