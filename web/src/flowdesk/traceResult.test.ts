import { describe, expect, it } from "vitest";
import type { PathResponse } from "../api/types";
import { FIXTURE_PATH_ECMP, FIXTURE_PATH_SINGLE } from "../test/fixtures";
import { groupByInterpretation, isBidirectional, isCompare, pickedStation, traceContext } from "./traceResult";

describe("traceResult", () => {
  it("narrows the compare and reply shapes", () => {
    expect(isCompare(FIXTURE_PATH_SINGLE)).toBe(false);
    expect(isBidirectional(FIXTURE_PATH_SINGLE)).toBe(false);
    const compare = { a: { snapshot: "1", result: FIXTURE_PATH_SINGLE }, b: { snapshot: "2", result: FIXTURE_PATH_SINGLE } };
    expect(isCompare(compare as never)).toBe(true);
    expect(isBidirectional({ forward: FIXTURE_PATH_SINGLE, reply: FIXTURE_PATH_SINGLE, notes: [] } as never)).toBe(true);
  });

  it("groups by interpretation only when the legs have more than one anchor", () => {
    expect(groupByInterpretation(FIXTURE_PATH_ECMP)).toBeNull();
    const [a, b] = FIXTURE_PATH_ECMP.legs;
    const split: PathResponse = {
      ...FIXTURE_PATH_ECMP,
      legs: [
        { ...a, interpretation: { anchor: "vrf:a", src_ip: "10.0.0.1", display: "VRF A" } },
        { ...b, interpretation: { anchor: "vrf:b", src_ip: "10.0.0.1", display: "VRF B" } },
      ] as PathResponse["legs"],
    };
    const groups = groupByInterpretation(split)!;
    expect(groups.map((g) => g.heading)).toEqual(["Assuming 10.0.0.1 in VRF A", "Assuming 10.0.0.1 in VRF B"]);
    expect(groups[0].result.legs).toHaveLength(1);
  });

  it("puts the submitted flow, the run and the clicked station in the page context", () => {
    const hop = FIXTURE_PATH_SINGLE.hops[0];
    const selection = { type: "hop" as const, data: hop };
    expect(pickedStation(selection, FIXTURE_PATH_SINGLE.hops)).toEqual({ uid: hop.uid, label: hop.label });
    const context = traceContext(
      { src: "10.0.0.1", dst: "10.0.0.2", proto: "tcp", port: "443", reply: false },
      "1700000000",
      selection,
      FIXTURE_PATH_SINGLE.hops,
    );
    expect(context.flow).toEqual({ src: "10.0.0.1", dst: "10.0.0.2", port: "443", proto: "tcp", reply: false });
    expect(context.snapshot).toEqual({ id: "1700000000", origin: "page-default", compare_id: undefined });
    expect(context.selection?.[0].uid).toBe(hop.uid);
  });
});
