import { describe, expect, it } from "vitest";
import type { TopologyModel } from "../api/types";
import { flowPaint } from "./flows";
import { connection, path } from "./flowFixture";

const dev = (id: string) => ({ id, kind: "device" as const, parent: "block:s:campus", label: id });

const MODEL: TopologyModel = {
  snapshot: 7,
  nodes: [dev("a"), dev("b"), dev("c"), dev("d")],
  cables: [
    { id: "a~b", from: { dev: "a", port: "e1" }, to: { dev: "b", port: "e1" }, source: "lldp", lateral: false },
    { id: "c~d", from: { dev: "c", port: "e1" }, to: { dev: "d", port: "e1" }, source: "lldp", lateral: false },
  ],
  exits: [],
  lags: [],
  split_groups: [],
};

const endpoint = (devices: string[]) => ({ member: "m", inventory_uid: "uid", devices, addresses: [] });

describe("flowPaint", () => {
  it("paints nothing when no connection is shown", () => {
    const p = flowPaint(MODEL, []);
    expect(p.classes.size).toBe(0);
    expect(p.extra).toEqual([]);
  });

  it("lights the drawn cable of a pair and draws a logical line where the drawing has none", () => {
    const p = flowPaint(MODEL, [connection({ id: "web", paths: [path({ devices: ["a", "b", "c"] })] })]);
    expect(p.classes.get("a~b")).toBe("fl-passes");
    expect(p.classes.get("c~d")).toBe("fl-off");
    expect(p.classes.get("a")).toBe("fl-on");
    expect(p.classes.get("d")).toBe("fl-off");
    expect(p.extra.map((e) => [e.data.source, e.data.target, e.classes])).toEqual([["b", "c", "flow-link fl-passes"]]);
    expect(p.note).toBe("1 connection, 1 path");
  });

  it("counts the devices of a path that the drawing does not hold, and draws no line to them", () => {
    const p = flowPaint(MODEL, [connection({ id: "web", paths: [path({ devices: ["a", "x", "y", "b"] })] })]);
    expect(p.offDrawing).toBe(2);
    expect(p.extra).toEqual([]);
    expect(p.note).toBe("1 connection, 1 path, 2 devices off this drawing");
  });

  it("marks the stop of a failing path and the first unknown of a path that is not established", () => {
    const failing = path({ devices: ["a", "b"], answer: "fails", stop_device: "b" });
    const open = path({
      devices: ["c", "d"],
      answer: "open",
      unknown_device: "d",
      segments: [{ from: "c", to: "d", phase: "forward", state: "open" }],
    });
    const p = flowPaint(MODEL, [connection({ id: "web", answer: "fails", paths: [failing, open] })]);
    expect(p.classes.get("b")).toBe("fl-on fl-stop");
    expect(p.classes.get("d")).toBe("fl-on fl-unknown");
    expect(p.classes.get("a~b")).toBe("fl-fails");
    expect(p.classes.get("c~d")).toBe("fl-open");
  });

  it("keeps the worst state of a cable two paths share", () => {
    const p = flowPaint(MODEL, [
      connection({ id: "web", paths: [path({ devices: ["a", "b"] })] }),
      connection({ id: "admin", answer: "fails", paths: [path({ devices: ["b", "a"], answer: "fails", stop_device: "a" })] }),
    ]);
    expect(p.classes.get("a~b")).toBe("fl-fails");
  });

  it("draws a dotted line between the endpoints of a connection with no evaluation, and only marks those of an unresolved one", () => {
    const p = flowPaint(MODEL, [
      connection({ id: "web", state: "not-evaluated", endpoints: { source: [endpoint(["a"])], destination: [endpoint(["c", "zz"])] } }),
      connection({ id: "admin", state: "unresolved", endpoints: { source: [endpoint(["d"])], destination: [] } }),
    ]);
    expect(p.extra.map((e) => [e.data.source, e.data.target, e.classes])).toEqual([["a", "c", "flow-link fl-not-evaluated"]]);
    expect(p.classes.get("a")).toBe("fl-endpoint fl-on");
    expect(p.classes.get("d")).toBe("fl-endpoint fl-on");
    expect(p.classes.get("a~b")).toBe("fl-off");
  });
});
