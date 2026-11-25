import { describe, expect, it } from "vitest";
import { detectMode, matches, parseQuery, rank, regexRefused } from "./match";

describe("detectMode", () => {
  it("reads each mode of the server grammar", () => {
    expect(detectMode("/edge.*/")).toBe("regex");
    expect(detectMode("//")).toBe("text");
    expect(detectMode("10.1.2.7")).toBe("ip");
    expect(detectMode("2001:db8::1")).toBe("ip");
    expect(detectMode("::ffff:10.0.0.1")).toBe("ip");
    expect(detectMode("10.1.2.0/24")).toBe("prefix");
    expect(detectMode("2001:db8::/32")).toBe("prefix");
    expect(detectMode("10.0.0.1-10.0.0.9")).toBe("range");
    expect(detectMode("10.0.0.1 - 10.0.0.9")).toBe("range");
    expect(detectMode("10.0.0.9-10.0.0.1")).toBe("text");
    expect(detectMode("10.0.0.1-2001:db8::1")).toBe("text");
    expect(detectMode("aa:bb:cc:dd:ee:ff")).toBe("mac");
    expect(detectMode("AA-BB-CC-DD-EE-FF")).toBe("mac");
    expect(detectMode("aabb.ccdd.eeff")).toBe("mac");
    expect(detectMode("aabbccddeeff")).toBe("mac");
    expect(detectMode("aa:bb-cc:dd:ee:ff")).toBe("text");
    expect(detectMode("10.1.2")).toBe("text");
    expect(detectMode("300.1.2.3")).toBe("text");
    expect(detectMode("edge1 gi0/1")).toBe("text");
  });
});

describe("matches", () => {
  it("matches every word of a text query in the label or the uid, ignoring case", () => {
    expect(matches("EDGE", "edge1")).toBe(true);
    expect(matches("edge hq", ["edge1", "dev:hq/edge1"])).toBe(true);
    expect(matches("edge dc", ["edge1", "dev:hq/edge1"])).toBe(false);
    expect(matches("", "anything")).toBe(true);
  });

  it("matches an address by equality, in a label or behind a uid namespace", () => {
    expect(matches("10.1.2.7", "10.1.2.7")).toBe(true);
    expect(matches("10.1.2.7", ["host", "ip:blue/10.1.2.7"])).toBe(true);
    expect(matches("10.1.2.7", "10.1.2.70")).toBe(false);
    expect(matches("2001:db8::1", "2001:0db8:0:0:0:0:0:1")).toBe(true);
  });

  it("matches the addresses inside a prefix and the equal prefix", () => {
    const q = parseQuery("10.1.2.0/24");
    expect(matches(q, "10.1.2.200")).toBe(true);
    expect(matches(q, "10.1.3.1")).toBe(false);
    expect(matches(q, "pfx:blue/10.1.2.0/24")).toBe(true);
    expect(matches(q, "10.1.2.0/25")).toBe(false);
    expect(matches("10.1.2.9/24", "10.1.2.0/24")).toBe(true);
  });

  it("matches the addresses inside a range", () => {
    expect(matches("10.0.0.1 - 10.0.0.9", "10.0.0.5")).toBe(true);
    expect(matches("10.0.0.1-10.0.0.9", "10.0.0.10")).toBe(false);
  });

  it("matches a MAC address on its hex digits in any notation", () => {
    expect(matches("aabb.ccdd.eeff", "port of AA:BB:CC:DD:EE:FF")).toBe(true);
    expect(matches("aa-bb-cc-dd-ee-ff", "aabbccddeeff")).toBe(true);
    expect(matches("aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:00")).toBe(false);
  });

  it("matches a regex on the whole value, ignoring case, and refuses what the server refuses", () => {
    expect(matches("/edge[0-9]+/", "EDGE12")).toBe(true);
    expect(matches("/edge/", "edge1")).toBe(false);
    expect(matches("/(edge/", "edge")).toBe(false);
    expect(matches("/(a)\\1/", "aa")).toBe(false);
    expect(matches("/edge(?=1)1/", "edge1")).toBe(false);
    expect(regexRefused("a".repeat(129))).toBe(true);
    expect(regexRefused("(?<name>a)")).toBe(false);
  });
});

describe("rank", () => {
  it("orders exact, prefix, contains, then a uid or word match", () => {
    expect(rank("s1d1", "s1d1", "dev:s1d1")).toBe(0);
    expect(rank("s1d1", "s1d10", "dev:s1d10")).toBe(1);
    expect(rank("d1", "s1d10", "dev:s1d10")).toBe(2);
    expect(rank("dev:", "s1d10", "dev:s1d10")).toBe(3);
    expect(rank("zzz", "s1d10", "dev:s1d10")).toBe(-1);
    expect(rank("10.1.2.7", "10.1.2.7")).toBe(0);
    expect(rank("10.1.2.0/24", "10.1.2.7")).toBe(2);
  });
});
