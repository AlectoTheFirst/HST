import { describe, expect, it } from "vitest";
import type { Hop, PathResponse } from "../../api/types";
import { createNullRenderer, type NullRenderer } from "../render/null";
import type { TableName } from "../render/types";
import { base, estate, tile, type Tables } from "../test/estate";
import { lanesOf, placeHops, routePoints } from "./place";

function load(t: Tables, tiles: string[]): NullRenderer {
  const r = createNullRenderer();
  r.setTier("layout", base(t));
  for (const name of ["render_t0", "render_t1", "render_t1_edges"] as TableName[]) r.setTier(name, t[name]);
  for (const block of tiles) {
    r.setTier("layout", tile(t, "layout", block), block);
    for (const name of ["render_t2_ports", "render_t2_cables"] as TableName[]) r.setTier(name, tile(t, name, block), block);
  }
  return r;
}

function hop(uid: string, kind: string, rank: number, extra: Partial<Hop> = {}): Hop {
  return { uid, kind, label: uid.split("/").pop() ?? uid, note: "", rank, lane: 0, shared: true, ...extra };
}

/** A trace from a client on s0d0 through s0d1 to s0d2, with a VRF and a prefix hop on s0d1 and a far-end endpoint. */
function trace(blocked = false): PathResponse {
  return {
    detail: blocked ? "blocked on s0d1" : "forwarded",
    notes: [],
    hops: [
      hop("ep:client", "Endpoint", 0),
      hop("dev:s0d0/port/eth1", "Port", 1),
      hop("dev:s0d0", "Device", 2),
      hop("dev:s0d1/port/eth0", "Port", 3),
      hop("dev:s0d1", "Device", 4),
      hop("vrf:s0d1:default", "VrfInstance", 5),
      hop("pfx:10.0.0.0/8", "Prefix", 6),
      hop("dev:s0d1/if/eth1", "Interface", 7),
      hop("dev:s0d2", "Device", 8),
      hop("ep:server", "Endpoint", 9),
      hop("dev:s0d3/port/eth0", "Port", 3, { lane: 1 }),
    ],
    legs: [{ lane: 0, sources: [], cidr: "10.0.0.0/8", egress: "eth1", next_hop: null, blocked, table: "default", src_label: "client", detail: "", fw_uid: blocked ? "dev:s0d1" : undefined }],
  } as unknown as PathResponse;
}

describe("the tunnel leg of a route", () => {
  it("rides the arc from the tunnel step to the next device and nests the carrier hops under the step", () => {
    const t = estate({ sites: 2, devices: 6, ports: 2 });
    const r = load(t, []);
    const result = {
      detail: "forwarded over the tunnel",
      notes: [],
      hops: [
        hop("dev:s0d0", "Device", 0),
        hop("tun:wg0", "Tunnel", 1, { label: "wg0" }),
        hop("dev:s1d1", "Device", 2),
        hop("dev:s0d0/port/eth1", "Port", 1, { overlay: 1, tunnel: "tun:wg0" }),
        hop("dev:s0d2", "Device", 2, { overlay: 1, tunnel: "tun:wg0" }),
      ],
      legs: [],
    } as unknown as PathResponse;
    const { steps } = placeHops(r.scene, result);
    expect(steps.map((s) => s.hop.uid)).toEqual(["dev:s0d0", "tun:wg0", "dev:s1d1"]);
    expect(steps[1].device).toBe("dev:s0d0");
    expect(steps[1].carrier?.map((h) => h.uid)).toEqual(["dev:s0d0/port/eth1", "dev:s0d2"]);
    const points = routePoints(r.scene, steps);
    const lifted = points.filter((p) => (p.y ?? 0) > 1);
    expect(lifted.length).toBeGreaterThan(3);
    expect(points[points.length - 1].label).toBe("dev:s1d1");
  });
});

describe("the hop placement", () => {
  const t = estate({ sites: 1, devices: 6, ports: 4 });

  it("puts every lane 0 hop on the map or in the off-map list, one time each", () => {
    const r = load(t, ["block:s0:campus"]);
    const { steps, offMap } = placeHops(r.scene, trace());
    const placed = steps.map((s) => s.hop.uid);
    const lane0 = trace().hops.filter((h) => h.lane === 0).map((h) => h.uid);
    expect([...placed, ...offMap.map((h) => h.uid)].sort()).toEqual([...lane0].sort());
    expect(offMap.map((h) => h.uid)).toEqual(["ep:client"]);
    expect(steps.find((s) => s.hop.uid === "vrf:s0d1:default")!.device).toBe("dev:s0d1");
    expect(steps.find((s) => s.hop.uid === "ep:server")!.device).toBe("dev:s0d2");
    expect(steps.find((s) => s.hop.uid === "dev:s0d0/port/eth1")!.uid).toBe("dev:s0d0/port/eth1");
    expect(steps.every((s) => !s.blocked)).toBe(true);
  });

  it("takes the device of a port when its tile is not loaded, and marks the blocking device", () => {
    const r = load(t, []);
    const { steps } = placeHops(r.scene, trace(true));
    expect(steps.find((s) => s.hop.uid === "dev:s0d0/port/eth1")!.uid).toBe("dev:s0d0");
    expect(steps.filter((s) => s.blocked).map((s) => s.hop.uid)).toEqual(["dev:s0d1"]);
  });

  it("routes along the cable between two devices when the tile is loaded", () => {
    const r = load(t, ["block:s0:campus"]);
    const { steps } = placeHops(r.scene, trace());
    const points = routePoints(r.scene, steps);
    expect(points.length).toBeGreaterThan(steps.length);
    expect(points[0].label).toBe("eth1");
    expect(points[points.length - 1].label).toBe("ep:server".split("/").pop());
    for (let i = 1; i < points.length; i++) expect(points[i].u !== points[i - 1].u || points[i].v !== points[i - 1].v).toBe(true);
    const bare = routePoints(load(t, []).scene, placeHops(load(t, []).scene, trace()).steps);
    expect(bare.length).toBeLessThan(points.length);
  });
});

describe("the hop placement of one lane", () => {
  const t = estate({ sites: 1, devices: 6, ports: 4 });

  it("names every lane and draws the picked one with the shared hops before the fork", () => {
    const r = load(t, []);
    expect(lanesOf(trace())).toEqual([0, 1]);
    const lane0 = placeHops(r.scene, trace()).steps.map((s) => s.hop.uid);
    const lane1 = placeHops(r.scene, trace(), 1).steps.map((s) => s.hop.uid);
    expect(lane0).not.toContain("dev:s0d3/port/eth0");
    expect(lane1).toContain("dev:s0d3/port/eth0");
    expect(lane1).toContain("dev:s0d0");
  });

  it("marks a rulebase blocked only on the lane whose leg it blocks", () => {
    const r = load(t, []);
    const rb = (lane: number) => hop("rb:fw", "FwRulebase", 5, { lane, shared: false });
    const base = trace();
    const result = {
      ...base,
      hops: [...base.hops.filter((h) => h.lane === 0), rb(0), hop("dev:s0d3", "Device", 4, { lane: 1, shared: false }), rb(1)],
      legs: [
        { ...base.legs[0], lane: 0, blocked: false, fw_uid: "rb:fw" },
        { ...base.legs[0], lane: 1, blocked: true, fw_uid: "rb:fw" },
      ],
    } as unknown as PathResponse;
    expect(placeHops(r.scene, result).steps.some((s) => s.blocked)).toBe(false);
    const lane1 = placeHops(r.scene, result, 1).steps;
    expect(lane1.filter((s) => s.blocked).map((s) => s.hop.uid)).toEqual(["rb:fw"]);
  });
});

describe("the hop placement of a leg with no rulebase to blame", () => {
  const t = estate({ sites: 1, devices: 6, ports: 4 });
  const withResult = (answer: "false" | "open", word: string): PathResponse => {
    const base = trace();
    const leg = { ...base.legs[0], blocked: false, result: { answer, word } };
    return { ...base, legs: [leg] } as unknown as PathResponse;
  };

  it("ends a no-route walk on a stop that carries the walk's word", () => {
    const r = load(t, ["block:s0:campus"]);
    const { steps } = placeHops(r.scene, withResult("false", "no route found"));
    expect(steps.filter((s) => s.blocked)).toHaveLength(1);
    const last = steps[steps.length - 1];
    expect(last.blocked).toBe(true);
    expect(last.word).toBe("no route found");
  });
  it("ends a no-route walk on the last step when the firewall that permitted it is named", () => {
    const r = load(t, ["block:s0:campus"]);
    const base = withResult("false", "no route found");
    const result = { ...base, legs: [{ ...base.legs[0], fw_uid: "dev:s0d1" }] } as unknown as PathResponse;
    const { steps } = placeHops(r.scene, result);
    expect(steps.filter((s) => s.blocked)).toHaveLength(1);
    const last = steps[steps.length - 1];
    expect(last.blocked).toBe(true);
    expect(last.word).toBe("no route found");
  });
  it("ends an undecided walk on a step with the word and no stop", () => {
    const r = load(t, ["block:s0:campus"]);
    const { steps } = placeHops(r.scene, withResult("open", "open"));
    expect(steps.some((s) => s.blocked)).toBe(false);
    expect(steps[steps.length - 1].word).toBe("open");
  });
  it("gives no word to a forwarded walk or a rulebase deny", () => {
    const r = load(t, ["block:s0:campus"]);
    expect(placeHops(r.scene, trace()).steps.some((s) => s.word)).toBe(false);
    const denied = placeHops(r.scene, trace(true)).steps;
    expect(denied.some((s) => s.blocked)).toBe(true);
    expect(denied.some((s) => s.word)).toBe(false);
  });
});
