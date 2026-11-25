import { describe, expect, it } from "vitest";
import { edgeState, edgeAnswer, structureElements, structureGraph } from "./structureModel";
import type { BusinessApplicationDefinition, FlowCheck } from "./types";

const DEFINITION = {
  schema_version: 1,
  kind: "BusinessApplication",
  id: "shop",
  name: "Shop",
  state: "draft",
  services: [],
  groups: [
    { id: "clients", name: "Clients", members: [{ id: "lan", address: "10.9.0.0/24" }] },
    { id: "servers", name: "Servers", members: [{ id: "web", address: "10.0.0.5" }] },
  ],
  connections: [
    { id: "web", name: "Web", source: "clients", destination: "servers", protocol: "tcp", destination_ports: [443], success: "forward" },
    { id: "api", name: "API", source: "clients", destination: "servers", protocol: "tcp", destination_ports: [8443], success: "forward" },
  ],
} as unknown as BusinessApplicationDefinition;

// The validate body's flows as the server sends them: `result`, no `verdict`.
const FLOWS: FlowCheck[] = [
  {
    connection_id: "web",
    readiness: "ready",
    result: { kind: "result", statement: "condition-holds", answer: "false", word: "fails", quantifier: "every", condition: "forward", missing: [] },
    passes: [],
    fails: ["10.9.0.0/25"],
    open: [],
    missing_evidence: [],
    not_evaluated_reason: null,
    detail: null,
  },
  { connection_id: "api", readiness: "ready", result: null, passes: [], fails: [], open: [], missing_evidence: [], not_evaluated_reason: "over-cap", detail: null },
];

describe("the structure graph read from a flow check result", () => {
  it("colours and captions an evaluated connection from result, without a verdict field", () => {
    expect(FLOWS[0]).not.toHaveProperty("verdict");
    const graph = structureGraph(DEFINITION, null, FLOWS);
    const web = graph.edges.find((edge) => edge.id === "web")!;
    expect(web.answer).toBe("fails");
    expect(edgeState(web)).toBe("Fails");
    const element = structureElements(graph).find((item) => item.data.id === "connection:web")!;
    expect(element.classes).toBe("fails");
    expect(element.data.caption).toBe("Web: Fails");
  });

  it("leaves a connection with a null result without an answer", () => {
    const graph = structureGraph(DEFINITION, null, FLOWS);
    const api = graph.edges.find((edge) => edge.id === "api")!;
    expect(api.result).toBeNull();
    expect(api.answer).toBeNull();
    expect(edgeState(api)).toBeNull();
  });

  it("maps each answer onto the class key the graph colours", () => {
    expect(edgeAnswer({ word: "passes", answer: "true" })).toBe("passes");
    expect(edgeAnswer({ word: "fails", answer: "false" })).toBe("fails");
    expect(edgeAnswer({ word: "not decided", answer: "open", missing: [{ code: "not-decided" }] })).toBe("open");
    expect(edgeAnswer(null)).toBeNull();
  });
});
