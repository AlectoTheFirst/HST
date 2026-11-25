import { describe, expect, it } from "vitest";
import { bySegment, matchCell, qosCell, routeLines, slaCell } from "./policy";
import { TOPOLOGY } from "./fixture";

const [fallback, voice] = TOPOLOGY.policy!.rules;

describe("policy cells", () => {
  it("reads the match summary, and the other match fields after it", () => {
    expect(matchCell(voice)).toBe("dscp 46 udp");
    expect(matchCell({ position: 1, match_summary: "any", match_src_vlan: 20 })).toBe("any; src vlan 20");
  });

  it("states one priority when tx and rx agree, and both when they differ", () => {
    expect(qosCell(voice)).toBe("realtime; priority high");
    expect(qosCell({ position: 1, qos_class: "transactional", priority_tx: "high", priority_rx: "low" })).toBe(
      "transactional; priority high tx, low rx",
    );
    expect(qosCell({ position: 1, bandwidth_cap_pct_tx: 20 })).toBe("cap 20% tx");
  });

  it("shows only the route action that the route type names", () => {
    expect(routeLines(voice)).toEqual([{ target: "to the cloud", text: "gateway; link auto" }]);
  });

  it("shows each route action when the rule has no route type", () => {
    const rule = { position: 1, edge2edge_route_policy: "direct", edge2datacenter_backhaul_hubs: ["H1", "H2"] };
    expect(routeLines(rule)).toEqual([
      { target: "to edges", text: "direct" },
      { target: "to data centres", text: "backhaul via H1, H2" },
    ]);
  });

  it("reads the SLA thresholds and the NAT", () => {
    expect(slaCell(voice)).toBe("latency 150 ms");
    expect(slaCell({ position: 1, nat_source: "10.0.0.1" })).toBe("source NAT 10.0.0.1");
    expect(slaCell(fallback)).toBe("");
  });

  it("groups the rules by segment in position order", () => {
    expect(bySegment(TOPOLOGY.policy!.rules)).toEqual([{ segment: "Global Segment", rules: [voice, fallback] }]);
  });
});
