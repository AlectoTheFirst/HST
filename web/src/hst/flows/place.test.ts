import { describe, expect, it } from "vitest";
import type { FlowConnection, FlowPath, FlowSegment, PathAnswer, Phase, SegmentState, ShownState } from "../../applications/flows";
import { conditionResult } from "../../netmap/flowFixture";
import { fit, zoomOf } from "../render/camera";
import { createNullRenderer, type NullRenderer } from "../render/null";
import { Y } from "../render/scene";
import { DEFAULT_STYLE, type TableName } from "../render/types";
import { base, estate, tile, type Tables } from "../test/estate";
import { placeFlows, REPLY_LIFT } from "./place";

const vp = { width: 1200, height: 800 };

function load(t: Tables, tiles: string[] = []): NullRenderer {
  const r = createNullRenderer();
  r.setTier("layout", base(t));
  for (const name of ["render_t0", "render_t1", "render_t1_edges"] as TableName[]) r.setTier(name, t[name]);
  for (const block of tiles) {
    r.setTier("layout", tile(t, "layout", block), block);
    for (const name of ["render_t2_ports", "render_t2_cables"] as TableName[]) r.setTier(name, tile(t, name, block), block);
  }
  const b = r.scene.bounds();
  const where = fit(b, vp);
  r.setCamera({ u: where.u, v: where.v, zoom: zoomOf(3) * 1.2 }, vp);
  return r;
}

const seg = (from: string, to: string, state: SegmentState, phase: Phase = "forward"): FlowSegment => ({ from, to, phase, state });

function path(outcome: PathAnswer, devices: string[], segments: FlowSegment[], extra: Partial<FlowPath> = {}): FlowPath {
  return {
    id: `${outcome}:${devices.join(">")}`,
    result: conditionResult(outcome),
    count: 1,
    members: ["db"],
    devices,
    phases: devices.map(() => "forward"),
    segments,
    steps: [],
    stop_index: null,
    stop_device: null,
    unknown_index: null,
    unknown_device: null,
    missing: [],
    ...extra,
  };
}

function connection(state: ShownState, paths: FlowPath[], extra: Partial<FlowConnection> = {}): FlowConnection {
  return {
    id: "web",
    name: "Web",
    result: state === "unresolved" || state === "not-evaluated" ? null : conditionResult(state),
    service_id: "shop",
    source: "clients",
    destination: "servers",
    protocol: "tcp",
    destination_ports: [443],
    success: "forward",
    readiness: state === "unresolved" ? "unresolved" : "ready",
    state: state === "unresolved" || state === "not-evaluated" ? state : "evaluated",
    issues: [],
    endpoints: {
      source: [{ member: "lan", inventory_uid: null, devices: ["dev:s0d0"], addresses: ["10.0.0.0/24"] }],
      destination: [{ member: "db", inventory_uid: "ip:db", devices: ["dev:s0d2"], addresses: ["10.1.0.5"] }],
    },
    evaluation: null,
    paths,
    more_paths: 0,
    counts: { passes: 0, fails: 0, open: 0 },
    missing: [],
    evidence_truncated: false,
    ...extra,
  };
}

describe("placeFlows", () => {
  const t = estate({ sites: 1, devices: 6, ports: 2 });

  it("draws a proven path as one solid route with pins, and lights its devices", () => {
    const r = load(t);
    const devices = ["dev:s0d0", "dev:s0d1", "dev:s0d2"];
    const placed = placeFlows(r.scene, [
      connection("passes", [path("passes", devices, [seg("dev:s0d0", "dev:s0d1", "passes"), seg("dev:s0d1", "dev:s0d2", "passes")])]),
    ]);
    const lines = placed.routes.filter((x) => x.line !== false);
    expect(lines.map((x) => x.state)).toEqual(["passes"]);
    expect(lines[0].points.length).toBeGreaterThanOrEqual(3);
    expect(placed.highlight).toEqual(new Set(devices));
    expect(placed.offMap.get("web")).toBe(0);
    const before = r.frame().drawCalls;
    r.setRoutes(placed.routes);
    const f = r.frame();
    expect(f.drawCalls).toBe(before + 1);
    expect(f.markers.map((m) => m.kind)).toEqual(["start", "end"]);
  });

  it("follows the cable between two devices when its tile is loaded", () => {
    const r = load(t, ["block:s0:campus"]);
    const cable = [...r.scene.rows("render_t2_cables")][0];
    const a = String(cable.a_dev);
    const b = String(cable.b_dev);
    const placed = placeFlows(r.scene, [connection("passes", [path("passes", [a, b], [seg(a, b, "passes")])])]);
    expect(placed.routes[0].points.length).toBeGreaterThan(2);
  });

  it("breaks the route at a device the drawing does not hold and counts it", () => {
    const r = load(t);
    const placed = placeFlows(r.scene, [
      connection("passes", [
        path("passes", ["dev:s0d0", "dev:far", "dev:s0d2"], [seg("dev:s0d0", "dev:far", "passes"), seg("dev:far", "dev:s0d2", "passes")]),
      ]),
    ]);
    expect(placed.routes.filter((x) => x.line !== false)).toEqual([]);
    expect(placed.offMap.get("web")).toBe(1);
    expect(placed.highlight.has("dev:far")).toBe(false);
  });

  it("draws a path that is not established as established up to the unknown device, then not established", () => {
    const r = load(t);
    const placed = placeFlows(r.scene, [
      connection("open", [
        path("open", ["dev:s0d0", "dev:s0d1", "dev:s0d2"], [seg("dev:s0d0", "dev:s0d1", "decided"), seg("dev:s0d1", "dev:s0d2", "open")], {
          unknown_device: "dev:s0d1",
        }),
      ]),
    ]);
    expect(placed.routes.filter((x) => x.line !== false).map((x) => x.state)).toEqual(["decided", "open"]);
  });

  it("draws a failing path up to its stop with the stop marker and no end pin", () => {
    const r = load(t);
    const placed = placeFlows(r.scene, [
      connection("fails", [path("fails", ["dev:s0d0", "dev:s0d1"], [seg("dev:s0d0", "dev:s0d1", "fails")], { stop_device: "dev:s0d1", stop_index: 3 })]),
    ]);
    expect(placed.routes.filter((x) => x.line !== false).map((x) => x.state)).toEqual(["fails"]);
    r.setRoutes(placed.routes);
    expect(r.frame().markers.map((m) => m.kind).sort()).toEqual(["start", "stop"]);
  });

  it("draws the reply phase as its own route above the forward one", () => {
    const r = load(t);
    const p = path(
      "passes",
      ["dev:s0d0", "dev:s0d1", "dev:s0d0"],
      [seg("dev:s0d0", "dev:s0d1", "passes"), seg("dev:s0d1", "dev:s0d0", "passes", "reply")],
      { phases: ["forward", "forward", "reply"] },
    );
    const placed = placeFlows(r.scene, [connection("passes", [p], { success: "round-trip" })]);
    const lines = placed.routes.filter((x) => x.line !== false);
    expect(lines).toHaveLength(2);
    expect(lines[0].points.every((pt) => pt.y === undefined)).toBe(true);
    expect(lines[1].points.every((pt) => pt.y === Y.route + REPLY_LIFT)).toBe(true);
  });

  it("draws a connection that is not evaluated as a dotted arc between its endpoints, never as a success", () => {
    const r = load(t);
    const placed = placeFlows(r.scene, [connection("not-evaluated", [])]);
    const lines = placed.routes.filter((x) => x.line !== false);
    expect(lines.map((x) => x.state)).toEqual(["not-evaluated"]);
    expect(lines[0].points.some((pt) => (pt.y ?? 0) > Y.route)).toBe(true);
    expect(placed.highlight).toEqual(new Set(["dev:s0d0", "dev:s0d2"]));
  });

  it("draws an unresolved connection as its endpoint pins only, and counts an endpoint outside the drawing", () => {
    const r = load(t);
    const c = connection("unresolved", []);
    c.endpoints.destination[0].devices = ["dev:s0d2", "dev:elsewhere"];
    const placed = placeFlows(r.scene, [c]);
    const before = r.frame().drawCalls;
    r.setRoutes(placed.routes);
    const f = r.frame();
    expect(f.drawCalls).toBe(before);
    expect(f.markers.map((m) => m.kind)).toEqual(["start", "end"]);
    expect(placed.offMap.get("web")).toBe(1);
  });

  it("dims the devices off a shown flow", () => {
    const r = load(t);
    const color = (uid: string) => {
      const b = r.scene.batches(r.frame().level).boxes.find((x) => x.cls === "device")!;
      const i = b.ids.indexOf(uid);
      return b.colors.slice(i * 3, i * 3 + 3);
    };
    const lit = color("dev:s0d1");
    r.setStyle({ ...DEFAULT_STYLE, highlight: new Set(["dev:s0d0"]) });
    expect(color("dev:s0d0")).toEqual(lit);
    expect(color("dev:s0d1")).not.toEqual(lit);
  });
});
