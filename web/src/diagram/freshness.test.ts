import { describe, expect, it } from "vitest";
import type { MapDevice } from "../api/types";
import { freshnessLabel, tableAges } from "./freshness";

const AT = Date.UTC(2026, 8, 5, 9, 30);

function device(over: Partial<MapDevice> = {}): MapDevice {
  return {
    uid: "dev:r1",
    name: "r1",
    role: "router",
    vendor: "cisco",
    model: null,
    mgmt_ip: "10.0.0.1",
    site: "home",
    ...over,
  };
}

describe("freshnessLabel", () => {
  it("says a failed device is unknown, and since when", () => {
    const label = freshnessLabel(device({ carried: true, carried_reason: "failed", last_seen: AT }));
    expect(label).toBe(`unknown since ${new Date(AT).toLocaleString()}`);
  });

  it("says unknown for a failed device with no last observation on record", () => {
    const label = freshnessLabel(device({ carried: true, carried_reason: "failed", last_seen: null }));
    expect(label).toBe("unknown");
  });

  it("never calls a carried device current, whatever carried it", () => {
    const reasons = ["failed", "not-run", "unchanged", "section-failed", null];
    for (const carried_reason of reasons) {
      const label = freshnessLabel(device({ carried: true, carried_reason, last_seen: AT }));
      expect(label).not.toBe("");
      expect(label).not.toMatch(/current|live/i);
    }
  });

  it("names why a carried device was carried", () => {
    const at = new Date(AT).toLocaleString();
    const of = (reason: string) =>
      freshnessLabel(device({ carried: true, carried_reason: reason, last_seen: AT }));
    expect(of("not-run")).toBe(`not collected in this run, last seen ${at}`);
    expect(of("unchanged")).toBe(`unchanged since the previous run, last seen ${at}`);
    expect(of("section-failed")).toBe(`part of this device was not collected, last seen ${at}`);
    expect(of("nothing-recorded")).toBe(`carried from an earlier run, last seen ${at}`);
  });

  it("badges nothing on a device this run collected", () => {
    expect(freshnessLabel(device({ carried: false, carried_reason: null, last_seen: AT }))).toBe("");
    expect(freshnessLabel(device())).toBe("");
  });
});

describe("tableAges", () => {
  it("reports each table's age, oldest first", () => {
    const d = device({
      tables: {
        arp: { status: "complete", observed_ms: AT, age_ms: 90_000 },
        rib: { status: "unchanged", observed_ms: AT - 7_200_000, age_ms: 7_290_000 },
      },
    });
    expect(tableAges(d)).toEqual(["rib 2 h", "arp 1 min"]);
  });

  it("leaves out a table whose observation time the run never recorded", () => {
    const d = device({
      tables: { arp: { status: "unchanged", observed_ms: null, age_ms: null } },
    });
    expect(tableAges(d)).toEqual([]);
    expect(tableAges(device())).toEqual([]);
  });
});
