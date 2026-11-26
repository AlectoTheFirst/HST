import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import type { Core } from "cytoscape";
import type { BusinessApplicationDefinition } from "../types";
import ComponentGraph from "./ComponentGraph";

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
const original = HTMLElement.prototype.getBoundingClientRect;
beforeAll(() => {
  HTMLElement.prototype.getBoundingClientRect = () =>
    ({ x: 0, y: 0, top: 0, left: 0, right: SIZE.width, bottom: SIZE.height, ...SIZE, toJSON: () => ({}) }) as DOMRect;
});
afterAll(() => {
  HTMLElement.prototype.getBoundingClientRect = original;
});
beforeEach(() => {
  instances.length = 0;
});

const DEFINITION: BusinessApplicationDefinition = {
  schema_version: 1,
  kind: "BusinessApplication",
  id: "webshop",
  name: "Webshop",
  state: "ready",
  services: [],
  groups: [
    { id: "frontend", name: "Frontend", members: [{ id: "vip", address: "10.1.10.5" }] },
    { id: "api", name: "API", members: [{ id: "a", address: "10.1.20.11" }, { id: "b", address: "10.1.20.12" }] },
  ],
  connections: [
    {
      id: "frontend-api",
      name: "Frontend to API",
      source: "frontend",
      destination: "api",
      protocol: "tcp",
      destination_ports: [8443],
      success: "forward",
      destination_condition: { kind: "member", member: "a", parts: [] },
    },
  ],
};

describe("ComponentGraph", () => {
  it("draws the components as boxes and the connections with their ports, and selects a component on a click", async () => {
    const onSelect = vi.fn();
    const { rerender } = render(<ComponentGraph definition={DEFINITION} selected={null} onSelect={onSelect} />);
    expect(await screen.findByRole("img", { name: "Component graph" })).toBeInTheDocument();
    const core = instances[0];
    expect(core.nodes().map((node) => node.data("caption"))).toEqual(["Frontend\n1 member", "API\n2 members"]);
    expect(core.$id("connection:frontend-api").data("caption")).toBe("tcp/8443");
    expect(core.nodes().map((node) => node.grabbable())).toEqual([false, false]);
    expect(screen.getByRole("list", { name: "Components and connections" })).toHaveTextContent("Frontend to API tcp/8443");

    core.$id("group:api").emit("tap");
    expect(onSelect).toHaveBeenCalledWith("api");

    rerender(<ComponentGraph definition={DEFINITION} selected="api" onSelect={onSelect} />);
    expect(core.$id("group:api").hasClass("on")).toBe(true);
    expect(core.$id("group:frontend").hasClass("on")).toBe(false);
  });
});
