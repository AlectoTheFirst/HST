/**
 * The growth path of the Explore graph, read from the Cytoscape instance. The
 * mock wraps the real constructor and keeps each instance it builds, as in
 * applications/ApplicationStructure.test.tsx. jsdom reports every element as
 * 0x0, so the viewport is stubbed.
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { render } from "@testing-library/react";
import type { Core } from "cytoscape";
import GraphView from "./GraphView";
import type { ResultGraph } from "../api/types";

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

const SIZE = { width: 900, height: 520 };
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
    ({ x: 0, y: 0, top: 0, left: 0, right: SIZE.width, bottom: SIZE.height, ...SIZE, toJSON: () => ({}) }) as DOMRect;
});

afterAll(() => {
  HTMLElement.prototype.getBoundingClientRect = original.rect;
  if (original.width) Object.defineProperty(HTMLElement.prototype, "clientWidth", original.width);
  if (original.height) Object.defineProperty(HTMLElement.prototype, "clientHeight", original.height);
});

beforeEach(() => {
  instances.length = 0;
});

const node = (id: string, hostname: string) => ({ id, labels: ["Device"], properties: { hostname } });
const rel = (id: string, start: string, end: string) => ({ id, type: "LINK", start, end, properties: {} });

const FIRST: ResultGraph = {
  nodes: [node("a", "core1"), node("b", "core2")],
  relationships: [rel("r1", "a", "b")],
  truncated: false,
};
const GROWN: ResultGraph = {
  nodes: [...FIRST.nodes, node("c", "edge1"), node("d", "edge2")],
  relationships: [...FIRST.relationships, rel("r2", "a", "c"), rel("r3", "a", "d")],
  truncated: false,
};

const positions = (core: Core) =>
  Object.fromEntries(core.nodes().map((n) => [n.id(), { ...n.position() }]));

describe("GraphView growth", () => {
  it("keeps one instance across a growth, and the drawn nodes keep their positions", () => {
    const { rerender } = render(<GraphView graph={FIRST} grows />);
    expect(instances).toHaveLength(1);
    const before = positions(instances[0]);
    rerender(<GraphView graph={GROWN} grows />);
    expect(instances).toHaveLength(1);
    expect(instances[0].nodes()).toHaveLength(4);
    const after = positions(instances[0]);
    expect(after.a).toEqual(before.a);
    expect(after.b).toEqual(before.b);
  });

  it("places one graph the same way on two renders at one stage size", () => {
    const first = render(<GraphView graph={GROWN} />);
    const one = positions(instances[0]);
    first.unmount();
    render(<GraphView graph={GROWN} />);
    expect(positions(instances[1])).toEqual(one);
  });
});
