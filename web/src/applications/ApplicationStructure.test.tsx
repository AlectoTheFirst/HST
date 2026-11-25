/** The tests cover the structure view in list and graph mode. */

import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { Core } from "cytoscape";
import { ApplicationStructure, structureGraph } from "./ApplicationStructure";
import type { BusinessApplicationDefinition, FlowCheck, ResolvedApplication } from "./types";

const { instances } = vi.hoisted(() => ({ instances: [] as Core[] }));

vi.mock("cytoscape", async (importOriginal) => {
  const actual = ((await importOriginal()) as { default: (options?: unknown) => Core }).default;
  const recording = Object.assign((options?: unknown) => {
    const core = actual(options);
    instances.push(core);
    return core;
  }, actual);
  return { default: recording };
});

const SIZE = { width: 900, height: 360 };
const original = {
  rect: HTMLElement.prototype.getBoundingClientRect,
  width: Object.getOwnPropertyDescriptor(HTMLElement.prototype, "clientWidth"),
  height: Object.getOwnPropertyDescriptor(HTMLElement.prototype, "clientHeight"),
};

beforeAll(() => {
  Object.defineProperties(HTMLElement.prototype, {
    clientWidth: { configurable: true, get: () => SIZE.width },
    clientHeight: { configurable: true, get: () => SIZE.height },
  });
  HTMLElement.prototype.getBoundingClientRect = () =>
    ({
      x: 0,
      y: 0,
      top: 0,
      left: 0,
      right: SIZE.width,
      bottom: SIZE.height,
      ...SIZE,
      toJSON: () => ({}),
    }) as DOMRect;
});

afterAll(() => {
  HTMLElement.prototype.getBoundingClientRect = original.rect;
  if (original.width) Object.defineProperty(HTMLElement.prototype, "clientWidth", original.width);
  if (original.height)
    Object.defineProperty(HTMLElement.prototype, "clientHeight", original.height);
});

beforeEach(() => {
  instances.length = 0;
});

const REFERENCE = {
  snapshot: "4000",
  manifest_sha256: "a".repeat(64),
  estate: "test",
  observation_floor_ms: null,
};

const DEFINITION: BusinessApplicationDefinition = {
  schema_version: 2,
  kind: "BusinessApplication",
  id: "webshop",
  name: "Webshop",
  state: "draft",
  services: [{ id: "shop", name: "Shop", connection_ids: ["web", "sql"], component_roles: [] }],
  groups: [
    { id: "clients", name: "Clients", members: [{ id: "lan", address: "10.9.0.0/24" }] },
    {
      id: "servers",
      name: "Servers",
      members: [
        {
          id: "web",
          name: "web01",
          placeholder: {
            text: "web01",
            expected_kind: "ip",
            status: "ambiguous",
            candidates: ["ip:blue:10.0.0.5", "ip:red:10.0.0.5"],
          },
        },
        { id: "app", address: "10.0.0.6" },
      ],
    },
    {
      id: "data",
      name: "Data",
      members: [
        { id: "db", inventory: { kind: "ip", uid: "ip:corp:10.0.0.9", role: "component" } },
      ],
    },
  ],
  connections: [
    {
      id: "web",
      name: "Web",
      source: "clients",
      destination: "servers",
      protocol: "tcp",
      destination_ports: [443],
      success: "forward",
      destination_condition: { kind: "member", member: "web", parts: [] },
    },
    {
      id: "sql",
      name: "SQL",
      source: "servers",
      destination: "data",
      protocol: "tcp",
      destination_ports: [5432],
      success: "session",
      destination_condition: { kind: "member", member: "db", parts: [] },
    },
  ],
};

const RESOLUTION: ResolvedApplication = {
  application: { id: "webshop", revision: 0, digest: "b".repeat(64) },
  snapshot: REFERENCE,
  digest: "c".repeat(64),
  ready: false,
  selection: { service_ids: [], connection_ids: ["web", "sql"] },
  groups: {},
  connections: [
    { id: "web", service_id: "shop", readiness: "unresolved", request: null, issues: [] },
    { id: "sql", service_id: "shop", readiness: "ready", request: null, issues: [] },
  ],
  issues: [],
};

const FLOWS: FlowCheck[] = [
  {
    connection_id: "web",
    readiness: "unresolved",
    result: null,
    passes: [],
    fails: [],
    open: [],
    missing_evidence: [],
    not_evaluated_reason: "not-ready",
    detail: null,
  },
  {
    connection_id: "sql",
    readiness: "ready",
    result: {
      kind: "result",
      statement: "condition-holds",
      answer: "true",
      word: "passes",
      quantifier: "every",
      condition: "forward",
      missing: [],
    },
    passes: ["10.0.0.6/32"],
    fails: [],
    open: [],
    missing_evidence: [],
    not_evaluated_reason: null,
    detail: null,
  },
];

describe("ApplicationStructure", () => {
  it("shows the list first and draws no graph until the graph mode is chosen", () => {
    render(<ApplicationStructure definition={DEFINITION} resolution={RESOLUTION} flows={FLOWS} />);

    const structure = screen.getByRole("region", { name: "Structure" });
    expect(within(structure).getByRole("button", { name: "List" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    expect(within(structure).getByRole("button", { name: "Graph" })).toHaveAttribute(
      "aria-pressed",
      "false",
    );
    expect(
      within(structure).getByRole("heading", { name: "Component groups" }),
    ).toBeInTheDocument();
    expect(within(structure).getByRole("cell", { name: "tcp, ports 5432" })).toBeInTheDocument();
    expect(within(structure).queryByRole("img")).not.toBeInTheDocument();
    expect(instances).toHaveLength(0);
  });

  it("draws the groups as nodes and the connections as edges, left to right", async () => {
    const user = userEvent.setup();
    render(<ApplicationStructure definition={DEFINITION} resolution={RESOLUTION} flows={FLOWS} />);
    await user.click(screen.getByRole("button", { name: "Graph" }));

    expect(await screen.findByRole("img", { name: "Dependency graph" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Component groups" })).not.toBeInTheDocument();
    expect(instances).toHaveLength(1);
    const core = instances[0];
    expect(core.nodes().map((node) => node.id())).toEqual([
      "group:clients",
      "group:servers",
      "group:data",
    ]);
    expect(core.edges().map((edge) => [edge.id(), edge.source().id(), edge.target().id()])).toEqual(
      [
        ["connection:web", "group:clients", "group:servers"],
        ["connection:sql", "group:servers", "group:data"],
      ],
    );
    // a group with a placeholder member has the dashed border
    expect(core.nodes().map((node) => node.hasClass("placeholder"))).toEqual([false, true, false]);
    expect(core.$id("group:servers").data("caption")).toBe("Servers\n2 members, 1 placeholder");
    expect(core.$id("connection:sql").hasClass("passes")).toBe(true);
    expect(core.$id("connection:sql").data("caption")).toBe("SQL: Passes");
    expect(core.$id("connection:web").hasClass("unresolved")).toBe(true);
    expect(core.$id("connection:web").data("caption")).toBe("Web: unresolved");
    const x = (id: string) => core.$id(id).position().x;
    expect(x("group:clients")).toBeLessThan(x("group:servers"));
    expect(x("group:servers")).toBeLessThan(x("group:data"));

    const text = screen.getByRole("list", { name: "Groups and connections" });
    expect(within(text).getByText("Group Servers: 2 members, 1 placeholder")).toBeInTheDocument();
    expect(within(text).getByText("Connection SQL: Servers to Data, Passes")).toBeInTheDocument();
    expect(
      within(text).getByText("Connection Web: Clients to Servers, unresolved"),
    ).toBeInTheDocument();
  });

  it("lays the groups out top to bottom in a narrow column", async () => {
    const wide = SIZE.width;
    SIZE.width = 240;
    try {
      const user = userEvent.setup();
      render(
        <ApplicationStructure definition={DEFINITION} resolution={RESOLUTION} flows={FLOWS} />,
      );
      await user.click(screen.getByRole("button", { name: "Graph" }));
      await screen.findByRole("img", { name: /Dependency graph/ });
      const core = instances[0];
      const y = (id: string) => core.$id(id).position().y;
      expect(y("group:clients")).toBeLessThan(y("group:servers"));
      expect(y("group:servers")).toBeLessThan(y("group:data"));
      expect(core.minZoom()).toBeLessThan(0.2);
      expect(core.$id("group:servers").style("min-zoomed-font-size")).not.toBe("0px");
    } finally {
      SIZE.width = wide;
    }
  });

  it("keeps the graph read-only", async () => {
    const user = userEvent.setup();
    const { unmount } = render(
      <ApplicationStructure definition={DEFINITION} resolution={RESOLUTION} flows={FLOWS} />,
    );
    await user.click(screen.getByRole("button", { name: "Graph" }));
    await screen.findByRole("img", { name: /Dependency graph/ });

    const core = instances[0];
    expect(core.autoungrabify()).toBe(true);
    expect(core.autounselectify()).toBe(true);
    expect(core.boxSelectionEnabled()).toBe(false);
    expect(core.nodes().map((node) => node.grabbable())).toEqual([false, false, false]);
    expect(core.elements().map((element) => element.selectable())).toEqual([
      false,
      false,
      false,
      false,
      false,
    ]);
    core.$id("group:servers").select();
    expect(core.$(":selected")).toHaveLength(0);
    // the view offers no control that changes the definition
    const structure = screen.getByRole("region", { name: "Structure" });
    expect(
      within(structure)
        .getAllByRole("button")
        .map((button) => button.textContent),
    ).toEqual(["List", "Graph", "Fit"]);
    expect(within(structure).queryAllByRole("textbox")).toHaveLength(0);
    expect(within(structure).queryAllByRole("combobox")).toHaveLength(0);

    await user.click(screen.getByRole("button", { name: "List" }));
    expect(core.destroyed()).toBe(true);
    unmount();
  });

  it("leaves out a connection whose group is not defined", () => {
    const orphan = {
      ...DEFINITION.connections[0],
      id: "orphan",
      name: "Orphan",
      destination: "cache",
    };
    const graph = structureGraph(
      { ...DEFINITION, connections: [...DEFINITION.connections, orphan] },
      null,
      null,
    );
    expect(graph.edges.map((edge) => [edge.id, edge.answer, edge.readiness])).toEqual([
      ["web", null, null],
      ["sql", null, null],
    ]);
  });
});
