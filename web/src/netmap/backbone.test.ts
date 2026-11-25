import { describe, expect, it } from "vitest";
import type { SiteGraphPayload } from "../api/types";
import {
  backbone,
  badgeOffset,
  BADGE_GAP,
  branchLinks,
  branchRows,
  homes,
  majorsOf,
  RING_CAP,
  ringPositions,
} from "./backbone";
import { DEFAULT_KINDS } from "./estate";
import { edge, PAYLOAD, site, SITES } from "./fixture";

/** the fixture with more sites and edges */
function plus(sites: SiteGraphPayload["sites"], edges: SiteGraphPayload["edges"]): SiteGraphPayload {
  return { ...PAYLOAD, sites: [...PAYLOAD.sites, ...sites], edges: [...PAYLOAD.edges, ...edges] };
}

describe("majorsOf", () => {
  it("returns the hubs, then the data centers, then the colocation sites, each by code", () => {
    expect(majorsOf(SITES).map((m) => [m.code, m.cls])).toEqual([
      ["fra-hub1", "hub"],
      ["fra-hub2", "hub"],
      ["ams-dc", "dc"],
      ["FR2", "colo"],
    ]);
  });
});

describe("backbone", () => {
  it("puts the 2 Berlin branches on the badge of fra-hub1 and muc-b1 in No hub", () => {
    const model = backbone(PAYLOAD, DEFAULT_KINDS);
    expect(model.majors.map((m) => m.code)).toEqual(["fra-hub1", "fra-hub2", "ams-dc", "FR2"]);
    expect(model.badges).toEqual([{ major: "fra-hub1", count: 2, branches: ["ber-b1", "ber-b2"] }]);
    expect(model.orphans).toContain("muc-b1");
    expect(model.orphans).toEqual(["muc-b1", "nowhere"]);
  });

  it("draws only major-to-major edges, with the count per kind", () => {
    const model = backbone(PAYLOAD, DEFAULT_KINDS);
    expect(model.edges).toEqual([{ a: "FR2", b: "fra-hub1", kinds: { cable: 4 }, total: 4 }]);
  });

  it("shows the BGP edge from ams-dc to fra-hub2 only when BGP is active", () => {
    const pair = (m: ReturnType<typeof backbone>) => m.edges.find((e) => e.a === "ams-dc" && e.b === "fra-hub2");
    expect(pair(backbone(PAYLOAD, DEFAULT_KINDS))).toBeUndefined();
    const withBgp = backbone(PAYLOAD, new Set([...DEFAULT_KINDS, "bgp"]));
    expect(pair(withBgp)).toEqual({ a: "ams-dc", b: "fra-hub2", kinds: { bgp: 3 }, total: 3 });
  });

  it("combines the kinds of one major pair into one edge", () => {
    const payload = plus([], [edge("fra-hub1", "FR2", "circuit", 2)]);
    expect(backbone(payload, DEFAULT_KINDS).edges).toEqual([
      { a: "FR2", b: "fra-hub1", kinds: { cable: 4, circuit: 2 }, total: 6 },
    ]);
  });

  it("moves the branches to No hub when tunnels are off", () => {
    const model = backbone(PAYLOAD, new Set(["cable", "circuit"]));
    expect(model.badges).toEqual([]);
    expect(model.orphans).toEqual(["ber-b1", "ber-b2", "muc-b1", "nowhere"]);
  });

  it("keeps a major site without coordinates in the backbone", () => {
    const payload = plus([site("lon-dc", null, null, { kind: "dc" })], [edge("lon-dc", "fra-hub1", "circuit", 2)]);
    const model = backbone(payload, DEFAULT_KINDS);
    expect(model.majors.map((m) => m.code)).toContain("lon-dc");
    expect(model.edges).toContainEqual({ a: "fra-hub1", b: "lon-dc", kinds: { circuit: 2 }, total: 2 });
  });
});

describe("homes", () => {
  it("counts a dual-homed branch only under the major site with the most links", () => {
    const payload = plus(
      [site("ham-b1", 53.55, 9.99, { tiers: { "sdwan-edge": 1 } })],
      [
        edge("ham-b1", "fra-hub1", "tunnel", 1),
        edge("fra-hub2", "ham-b1", "tunnel", 2),
        edge("ham-b1", "fra-hub2", "circuit", 1),
        edge("ham-b1", "ams-dc", "cable", 1),
      ],
    );
    const home = homes(payload, DEFAULT_KINDS).get("ham-b1")!;
    expect(home.primary).toBe("fra-hub2");
    expect(home.others).toEqual(["ams-dc", "fra-hub1"]);
    expect(home.counts).toEqual({ "fra-hub1": 1, "fra-hub2": 3, "ams-dc": 1 });
    expect(home.total).toBe(5);

    const model = backbone(payload, DEFAULT_KINDS);
    expect(model.badges.map((b) => [b.major, b.count])).toEqual([
      ["fra-hub1", 2],
      ["fra-hub2", 1],
    ]);
    // with only cables active, the data center is the one major neighbor
    expect(homes(payload, new Set(["cable"])).get("ham-b1")!.primary).toBe("ams-dc");
  });

  it("gives a tie to the lower code in code point order", () => {
    const payload = plus(
      [site("ham-b1", 53.55, 9.99), site("ham-b2", 53.56, 9.98)],
      [
        edge("ham-b1", "fra-hub2", "tunnel", 2),
        edge("ham-b1", "fra-hub1", "tunnel", 2),
        // upper case sorts first: FR2 wins over fra-hub1
        edge("ham-b2", "fra-hub1", "tunnel", 1),
        edge("ham-b2", "FR2", "cable", 1),
      ],
    );
    const all = homes(payload, DEFAULT_KINDS);
    expect(all.get("ham-b1")).toMatchObject({ primary: "fra-hub1", others: ["fra-hub2"] });
    expect(all.get("ham-b2")).toMatchObject({ primary: "FR2", others: ["fra-hub1"] });
  });

  it("gives no home to a branch whose only links are to branches", () => {
    expect(homes(PAYLOAD, DEFAULT_KINDS).get("muc-b1")).toEqual({
      code: "muc-b1",
      primary: null,
      others: [],
      counts: {},
      total: 1,
    });
  });
});

describe("branchRows and branchLinks", () => {
  it("lists the branches of one badge and of No hub", () => {
    expect(branchRows(PAYLOAD, DEFAULT_KINDS, "fra-hub1")).toEqual([
      { code: "ber-b1", name: "ber-b1", others: [], total: 4 },
      { code: "ber-b2", name: "ber-b2", others: [], total: 3 },
    ]);
    expect(branchRows(PAYLOAD, DEFAULT_KINDS, null).map((r) => r.code)).toEqual(["muc-b1", "nowhere"]);
  });

  it("links the shown branches to the major sites and to each other, not to hidden branches", () => {
    expect(branchLinks(PAYLOAD, DEFAULT_KINDS, "fra-hub1").map((l) => `${l.a}~${l.b}`)).toEqual([
      "ber-b1~ber-b2",
      "ber-b1~fra-hub1",
      "ber-b2~fra-hub1",
    ]);
    // muc-b1 links to ber-b1, which shows only when the hub badge is open too
    expect(branchLinks(PAYLOAD, DEFAULT_KINDS, null)).toEqual([]);
    expect(branchLinks(PAYLOAD, DEFAULT_KINDS, ["fra-hub1", null]).map((l) => `${l.a}~${l.b}`)).toContain(
      "ber-b1~muc-b1",
    );
  });
});

describe("ringPositions", () => {
  const center = { x: 100, y: 50 };
  const away = { x: 3, y: -4 };
  const size = 12;

  function nearest(points: { x: number; y: number }[]): number {
    let best = Infinity;
    for (let i = 0; i < points.length; i++)
      for (let j = i + 1; j < points.length; j++)
        best = Math.min(best, Math.hypot(points[i].x - points[j].x, points[i].y - points[j].y));
    return best;
  }

  it.each([1, 12, 200])("gives the same positions each time, with no overlap, for %i branches", (n) => {
    const first = ringPositions(center, away, n, size);
    expect(ringPositions(center, away, n, size)).toEqual(first);
    expect(first).toHaveLength(Math.min(n, RING_CAP));
    if (first.length > 1) expect(nearest(first)).toBeGreaterThanOrEqual(size - 1e-9);
    // every branch clears the major site and its badge
    for (const p of first) expect(Math.hypot(p.x - center.x, p.y - center.y)).toBeGreaterThan(BADGE_GAP + size);
  });

  it("opens toward the away side", () => {
    const [only] = ringPositions(center, away, 1, size);
    const dx = only.x - center.x;
    const dy = only.y - center.y;
    expect(dx / Math.hypot(dx, dy)).toBeCloseTo(0.6, 9);
    expect(dy / Math.hypot(dx, dy)).toBeCloseTo(-0.8, 9);
    for (const p of ringPositions(center, away, 12, size)) {
      expect((p.x - center.x) * away.x + (p.y - center.y) * away.y).toBeGreaterThanOrEqual(-1e-9);
    }
  });

  it("caps the positions so the caller can show the rest as one node", () => {
    expect(RING_CAP).toBe(120);
    expect(ringPositions(center, away, 200, size)).toHaveLength(120);
    expect(ringPositions(center, away, 0, size)).toEqual([]);
  });
});

describe("badgeOffset", () => {
  it("puts the badge a fixed distance away on the away side", () => {
    const at = badgeOffset({ x: 10, y: 10 }, { x: 0, y: 5 });
    expect(at).toEqual({ x: 10, y: 10 + BADGE_GAP });
    expect(badgeOffset({ x: 0, y: 0 }, { x: 0, y: 0 })).toEqual({ x: BADGE_GAP, y: 0 });
  });
});
