import { describe, it, expect } from "vitest";
import { buildScene, linkHiddenByLayers, visibleLinks } from "./scene";
import { layerOf } from "./layers";
import {
  FIXTURE_PATH_SINGLE,
  FIXTURE_PATH_ECMP,
  FIXTURE_PATH_PARTITION,
  FIXTURE_PATH_BLOCKED,
  hop as hopFields,
} from "../../test/fixtures";

describe("buildScene: geometry is a direct read of rank, lane and layer", () => {
  it("single path: one node per hop, cell is a direct read of rank/lane", () => {
    const scene = buildScene(FIXTURE_PATH_SINGLE);
    expect(scene.nodes).toHaveLength(FIXTURE_PATH_SINGLE.hops.length);
    for (const node of scene.nodes) {
      const hop = FIXTURE_PATH_SINGLE.hops.find((h) => h.rank === node.rank)!;
      expect(node.cell).toEqual({ q: hop.rank, r: hop.lane });
      expect(node.layer).toBe(layerOf(hop.kind));
      expect(node.dimmed).toBe(false);
    }
  });

  it("never recomputes ordering: nodes are a 1:1 map over the input hops", () => {
    const scene = buildScene(FIXTURE_PATH_ECMP);
    expect(scene.nodes.map((n) => n.uid + ":" + n.lane + ":" + n.rank)).toEqual(
      FIXTURE_PATH_ECMP.hops.map((h) => h.uid + ":" + h.lane + ":" + h.rank),
    );
  });

  it("gives an identical scene for the same input twice", () => {
    const s1 = buildScene(FIXTURE_PATH_PARTITION);
    const s2 = buildScene(FIXTURE_PATH_PARTITION);
    expect(s1).toEqual(s2);
  });

  it("layerCount matches the STRATA_LAYERS stack", () => {
    expect(buildScene(FIXTURE_PATH_SINGLE).layerCount).toBe(4);
  });
});

describe("buildScene: edge and drop classification", () => {
  it("classifies every connector by whether the two hops share a layer", () => {
    const scene = buildScene(FIXTURE_PATH_PARTITION);
    const byKey = new Map(scene.nodes.map((n) => [`${n.uid}:${n.lane}:${n.rank}`, n]));

    for (const edge of scene.edges) {
      expect(byKey.get(edge.from)!.layer).toBe(byKey.get(edge.to)!.layer);
    }
    for (const drop of scene.drops) {
      expect(byKey.get(drop.from)!.layer).not.toBe(byKey.get(drop.to)!.layer);
    }
    expect(scene.drops.length).toBeGreaterThan(0);
  });

  it("connects the whole walk as a tree: every hop but the spine's first has exactly one incoming connector", () => {
    for (const fixture of [FIXTURE_PATH_ECMP, FIXTURE_PATH_PARTITION, FIXTURE_PATH_SINGLE]) {
      const scene = buildScene(fixture);
      expect(scene.edges.length + scene.drops.length).toBe(fixture.hops.length - 1);
    }
  });

  it("draws no connector into a lane's first hop when there is no shared spine", () => {
    const scene = buildScene({
      hops: [
        { uid: "a", kind: "Interface", label: "a", note: "", rank: 0, lane: 0, shared: false },
        { uid: "b", kind: "Interface", label: "b", note: "", rank: 0, lane: 1, shared: false },
      ],
      legs: [
        { lane: 0, sources: [], cidr: null, egress: null, next_hop: null, blocked: false, table: null, src_label: "x", ...hopFields("") },
        { lane: 1, sources: [], cidr: null, egress: null, next_hop: null, blocked: false, table: null, src_label: "y", ...hopFields("") },
      ],
    });
    expect(scene.edges).toHaveLength(0);
    expect(scene.drops).toHaveLength(0);
  });
});

describe("buildScene: blocked-lane dead flags", () => {
  it("no connector is dead on a real fixture: path.py never emits hops past a block", () => {
    const scene = buildScene(FIXTURE_PATH_BLOCKED);
    expect([...scene.edges, ...scene.drops].every((c) => c.dead === false)).toBe(true);
  });

  it("marks the not-drawn remainder past the gate dead, and dims the whole blocked lane", () => {
    const scene = buildScene({
      hops: [
        { uid: "if:gw", kind: "Interface", label: "gw", note: "", rank: 0, lane: 0, shared: true },
        { uid: "gate", kind: "FwRulebase", label: "RB", note: "", rank: 1, lane: 0, shared: false },
        { uid: "post", kind: "Interface", label: "post-gate", note: "dst 10.0.0.5", rank: 2, lane: 0, shared: false },
      ],
      legs: [
        {
          lane: 0, sources: [], cidr: null, egress: null, next_hop: null,
          blocked: true, table: null, src_label: "x", ...hopFields("BLOCKED by RB", true),
        },
      ],
    });

    const links = [...scene.edges, ...scene.drops];
    const intoGate = links.find((l) => l.to === "gate:0:1")!;
    const pastGate = links.find((l) => l.from === "gate:0:1")!;
    expect(intoGate.dead).toBe(false); // reached the gate
    expect(pastGate.dead).toBe(true); // past the gate

    const gwNode = scene.nodes.find((n) => n.uid === "if:gw")!;
    const gateNode = scene.nodes.find((n) => n.uid === "gate")!;
    const postNode = scene.nodes.find((n) => n.uid === "post")!;
    expect(gwNode.dimmed).toBe(false); // shared spine hop: never dims
    expect(gateNode.dimmed).toBe(true); // the gate itself dims
    expect(postNode.dimmed).toBe(true); // drawn past the gate
  });

  it("the shared spine is never dead, even feeding into an all-blocked lane", () => {
    const scene = buildScene(FIXTURE_PATH_BLOCKED);
    const spineHops = FIXTURE_PATH_BLOCKED.hops.filter((h) => h.shared);
    const spineKeys = new Set(spineHops.map((h) => `${h.uid}:${h.lane}:${h.rank}`));
    for (const edge of scene.edges) {
      if (spineKeys.has(edge.from) && spineKeys.has(edge.to)) expect(edge.dead).toBe(false);
    }
  });
});

describe("buildScene: verdict placement", () => {
  it("puts the leg verdict on the rulebase that decided it: pass", () => {
    const fw = FIXTURE_PATH_PARTITION.hops.find((h) => h.kind === "FwRulebase")!;
    const withVerdict = {
      ...FIXTURE_PATH_PARTITION,
      legs: FIXTURE_PATH_PARTITION.legs.map((l) => ({ ...l, fw_uid: fw.uid })),
    };
    const scene = buildScene(withVerdict);
    const node = scene.nodes.find((n) => n.uid === fw.uid)!;
    expect(node.verdict).toBe("ok");
  });

  it("marks the deciding rulebase of a blocked leg as bad", () => {
    const scene = buildScene(FIXTURE_PATH_BLOCKED);
    const fw = FIXTURE_PATH_BLOCKED.hops.find((h) => h.kind === "FwRulebase")!;
    const node = scene.nodes.find((n) => n.uid === fw.uid)!;
    expect(node.verdict).toBe("bad");
  });

  it("marks an indeterminate leg's rulebase as warn, never a pass", () => {
    const fw = FIXTURE_PATH_PARTITION.hops.find((h) => h.kind === "FwRulebase")!;
    const scene = buildScene({
      ...FIXTURE_PATH_PARTITION,
      legs: [{ ...FIXTURE_PATH_PARTITION.legs[0], fw_uid: fw.uid, indeterminate: true }],
    });
    const node = scene.nodes.find((n) => n.uid === fw.uid)!;
    expect(node.verdict).toBe("warn");
  });

  it("marks upstream rulebases in fw_uids as a plain pass", () => {
    const fw = FIXTURE_PATH_PARTITION.hops.find((h) => h.kind === "FwRulebase")!;
    const scene = buildScene({
      ...FIXTURE_PATH_PARTITION,
      legs: FIXTURE_PATH_PARTITION.legs.map((l) => ({ ...l, fw_uids: [fw.uid] })),
    });
    const node = scene.nodes.find((n) => n.uid === fw.uid)!;
    expect(node.verdict).toBe("ok");
  });

  it("a shared gate in an all-blocked trace reads as failed with no fw_uid pointing at it", () => {
    const scene = buildScene({
      hops: [
        { uid: "rb", kind: "FwRulebase", label: "RB", note: "", rank: 0, lane: 0, shared: true },
        { uid: "post", kind: "Interface", label: "post", note: "", rank: 1, lane: 0, shared: false },
      ],
      legs: [
        { lane: 0, sources: [], cidr: null, egress: null, next_hop: null, blocked: true, table: null, src_label: "x", ...hopFields("", true) },
      ],
    });
    const node = scene.nodes.find((n) => n.uid === "rb")!;
    expect(node.verdict).toBe("bad");
  });

  it("an ACI contract deny colours its own shared hop", () => {
    const scene = buildScene({
      hops: [
        { uid: "k:web-db", kind: "Contract", label: "web-to-db", note: "deny", rank: 0, lane: 0, shared: true },
        { uid: "rb", kind: "FwRulebase", label: "RB", note: "", rank: 1, lane: 0, shared: false },
        { uid: "rb", kind: "FwRulebase", label: "RB", note: "", rank: 1, lane: 1, shared: false },
      ],
      legs: [
        { lane: 0, sources: [], cidr: null, egress: null, next_hop: null, blocked: true, table: null, src_label: "x", ...hopFields("", true), fw_uid: "rb", blocking_uid: "k:web-db" },
        { lane: 1, sources: [], cidr: null, egress: null, next_hop: null, blocked: true, table: null, src_label: "y", ...hopFields("", true), fw_uid: "rb", blocking_uid: "k:web-db" },
      ],
    });
    const contract = scene.nodes.filter((n) => n.uid === "k:web-db");
    expect(contract).toHaveLength(1);
    expect(contract[0].shared).toBe(true);
    expect(contract[0].verdict).toBe("bad");
  });

  it("a non-gate kind never gets a verdict, even sitting on the deciding leg's lane", () => {
    const scene = buildScene(FIXTURE_PATH_PARTITION);
    const nonGate = scene.nodes.filter((n) => n.kind !== "FwRulebase" && n.kind !== "PbrPolicy");
    expect(nonGate.every((n) => n.verdict === null)).toBe(true);
  });
});

describe("linkHiddenByLayers and visibleLinks: lane geometry follows the layer toggle", () => {
  it("hides a link only once both its layers are hidden; one visible end keeps it", () => {
    const hidden = new Set([0, 1]);
    expect(linkHiddenByLayers(0, 1, hidden)).toBe(true);
    expect(linkHiddenByLayers(1, 2, hidden)).toBe(false); // 2 stays visible
    expect(linkHiddenByLayers(0, 0, hidden)).toBe(true);
    expect(linkHiddenByLayers(2, 3, hidden)).toBe(false);
  });

  it("returns the scene's own arrays when every layer is on", () => {
    const scene = buildScene(FIXTURE_PATH_PARTITION);
    expect(visibleLinks(scene)).toEqual({ edges: scene.edges, drops: scene.drops });
    expect(visibleLinks(scene, new Set())).toEqual({ edges: scene.edges, drops: scene.drops });
  });

  it("emits no lane segment when every layer is hidden", () => {
    const scene = buildScene(FIXTURE_PATH_PARTITION);
    expect(scene.edges.length + scene.drops.length).toBeGreaterThan(0);
    const { edges, drops } = visibleLinks(scene, new Set([0, 1, 2, 3]));
    expect(edges).toHaveLength(0);
    expect(drops).toHaveLength(0);
  });

  it("drops a segment with both stations hidden and keeps a segment with one visible station", () => {
    // physical -> routing -> policy -> policy, one shared spine, one lane.
    const scene = buildScene({
      hops: [
        { uid: "h0", kind: "Interface", label: "h0", note: "", rank: 0, lane: 0, shared: true }, // physical (0)
        { uid: "h1", kind: "VrfInstance", label: "h1", note: "", rank: 1, lane: 0, shared: true }, // routing (1)
        { uid: "h2", kind: "FwRulebase", label: "h2", note: "", rank: 2, lane: 0, shared: true }, // policy (2)
        { uid: "h3", kind: "Zone", label: "h3", note: "", rank: 3, lane: 0, shared: true }, // policy (2)
      ],
      legs: [
        { lane: 0, sources: [], cidr: null, egress: null, next_hop: null, blocked: false, table: null, src_label: "x", ...hopFields("") },
      ],
    });
    expect(scene.drops.map((d) => [d.from, d.to])).toEqual([
      ["h0:0:0", "h1:0:1"],
      ["h1:0:1", "h2:0:2"],
    ]);
    expect(scene.edges.map((e) => [e.from, e.to])).toEqual([["h2:0:2", "h3:0:3"]]);

    // Hiding only routing (1): every link still has a visible end, so nothing drops.
    const routingHidden = visibleLinks(scene, new Set([1]));
    expect(routingHidden.drops).toHaveLength(2);
    expect(routingHidden.edges).toHaveLength(1);

    const physicalAndRoutingHidden = visibleLinks(scene, new Set([0, 1]));
    expect(physicalAndRoutingHidden.drops.map((d) => [d.from, d.to])).toEqual([
      ["h1:0:1", "h2:0:2"],
    ]);
    expect(physicalAndRoutingHidden.edges).toHaveLength(1); // policy->policy edge untouched
  });
});
