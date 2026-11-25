import { describe, expect, it } from "vitest";
import { Scene } from "../render/scene";
import { estate } from "../test/estate";
import { search } from "./find";
import { transports } from "./tunnels";

describe("search", () => {
  const scene = new Scene();
  const t = estate({ sites: 3, devices: 12, ports: 0 });
  scene.setTier("render_t0", t.render_t0);
  scene.setTier("render_t1", t.render_t1);

  it("finds devices, sites and blocks, the exact match first", () => {
    expect(search(scene, "s1d1").map((h) => h.uid)).toEqual(["dev:s1d1", "dev:s1d10", "dev:s1d11"]);
    expect(search(scene, "s2")[0]).toEqual({ uid: "site:s2", kind: "site", label: "s2" });
    expect(search(scene, "campus")[0].kind).toBe("block");
    expect(search(scene, "  ")).toEqual([]);
    expect(search(scene, "d", 5)).toHaveLength(5);
  });
});

describe("tunnel transports", () => {
  it("groups the device's tunnels by far end and transport", () => {
    const edges = [
      { pair_id: "a|b", a_uid: "a", b_uid: "b", tunnel_count: 3 },
      { pair_id: "a|c", a_uid: "a", b_uid: "c", tunnel_count: 0 },
    ];
    const tier3 = {
      uid: "a",
      snapshot: 1,
      state: "warm" as const,
      categories: {},
      contexts: [],
      tunnels: [
        { uid: "t1", encap: "ipsec", other: "b" },
        { uid: "t2", encap: "gre", other: "b" },
        { uid: "t3", encap: "ipsec", other: "b" },
      ],
    };
    expect(transports("a", tier3, edges)).toEqual(
      new Map([["a|b", [{ encap: "ipsec", count: 2 }, { encap: "gre", count: 1 }]]]),
    );
  });
});
