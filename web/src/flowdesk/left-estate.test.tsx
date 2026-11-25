import { describe, it, expect } from "vitest";
import { render } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Inspector } from "./Inspector";
import { TraceRender } from "./TraceGroups";
import { exitText, groupByInterpretation, paneExits } from "./traceResult";
import { FIXTURE_PATH_SINGLE } from "../test/fixtures";
import type { EstateExit, PathResponse, WalkReach } from "../api/types";

const ZONE: EstateExit = {
  basis: "site-zone",
  device_uid: "dev:edge1",
  device: "edge1",
  interface_uid: "if:edge1:gi0",
  interface: "Gi0/0/0",
  next_hop: "198.51.100.1",
  wan_link_uid: null,
  wan_link: null,
  site_block: "dc-edge",
};
const WAN: EstateExit = {
  ...ZONE,
  basis: "wan-link",
  device_uid: "dev:vyos",
  device: "vyos",
  interface: "eth0",
  next_hop: null,
  wan_link_uid: "wan:1",
  wan_link: "isp-a",
  site_block: null,
};

function edge(reach: WalkReach | undefined, exit: EstateExit | undefined = ZONE): PathResponse {
  const leg = FIXTURE_PATH_SINGLE.legs[0];
  const out: PathResponse = { ...FIXTURE_PATH_SINGLE, legs: [{ ...leg, ...(exit ? { left_estate: exit } : {}) }] };
  if (reach !== undefined) {
    out.reach = reach;
    out.left_estate = exit ? [exit] : [];
  }
  return out;
}

function wrap(node: React.ReactNode) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
}

function pane(result: PathResponse) {
  return wrap(<TraceRender view="tree" result={result} selection={null} onSelect={() => {}} />);
}

describe("exit words", () => {
  it("names device, interface, next hop and basis", () => {
    expect(exitText(ZONE)).toBe('edge1 Gi0/0/0 next-hop 198.51.100.1 (site zone "internet" of block dc-edge)');
    expect(exitText(WAN)).toBe("vyos eth0 no next hop (collected WAN link isp-a)");
    expect(exitText({ ...ZONE, basis: "access-client-default", device: null, interface: null })).toBe(
      "dev:edge1 if:edge1:gi0 next-hop 198.51.100.1 (access client's default)",
    );
    expect(exitText({ ...ZONE, site_block: null })).toBe('edge1 Gi0/0/0 next-hop 198.51.100.1 (site zone "internet")');
  });

  it("states exits only for a walk that left the estate, from the pane's own legs", () => {
    expect(paneExits(edge("left_estate"))).toEqual([ZONE]);
    expect(paneExits(edge("split"))).toEqual([ZONE]);
    expect(paneExits(edge("destination"))).toEqual([]);
    expect(paneExits(edge(null))).toEqual([]);
    expect(paneExits(edge(undefined))).toEqual([]);
    // an interpretation pane holds only some of the walk's legs
    const two = edge("split");
    const leg = FIXTURE_PATH_SINGLE.legs[0];
    two.legs = [
      { ...leg, lane: 0, interpretation: { src_ip: "10.0.0.1", anchor: "a", display: "a" }, left_estate: ZONE },
      { ...leg, lane: 1, interpretation: { src_ip: "10.0.0.1", anchor: "b", display: "b" } },
    ];
    const groups = groupByInterpretation(two)!;
    expect(groups.map((g) => paneExits(g.result))).toEqual([[ZONE], []]);
  });
});

describe("trace pane", () => {
  it("says left estate and the exit for a walk that left the estate", () => {
    for (const [reach, label] of [["left_estate", "Left estate"], ["split", "Left estate per path"]] as const) {
      const { container, unmount } = pane(edge(reach));
      const line = container.querySelector(".trace-reach");
      expect(line?.querySelector(".eyebrow")?.textContent).toBe(label);
      expect(line?.textContent).toContain('edge1 Gi0/0/0 next-hop 198.51.100.1 (site zone "internet" of block dc-edge)');
      unmount();
    }
  });

  it("shows the same markup for a walk without the field, null or destination", () => {
    // React's generated ids differ from one mount to the next
    const html = (el: Element) => el.innerHTML.replace(/_r_\w+_/g, "_r_");
    const first = pane(FIXTURE_PATH_SINGLE);
    const before = html(first.container);
    first.unmount();
    for (const result of [edge(undefined), edge(null), edge("destination")]) {
      const { container, unmount } = pane(result);
      expect(container.querySelector(".trace-reach")).toBeNull();
      expect(html(container)).toBe(before);
      unmount();
    }
  });
});

describe("node details", () => {
  it("names the exit of the selected leg", () => {
    const result = edge("left_estate", WAN);
    const { container } = wrap(
      <Inspector selection={{ type: "leg", data: result.legs[0] }} result={result} open onToggle={() => {}} />,
    );
    expect(container.querySelector(".inspector-leg")?.textContent).toContain(
      "left estate vyos eth0 no next hop (collected WAN link isp-a)",
    );
  });
});

// hst/results/words.py FORBIDDEN_WORDS, plus its spaced form
const FORBIDDEN = [
  "proven", "possible", "holds", "does-not-hold", "not-established", "not established", "indeterminate",
  "mixed", "reached", "reachable", "reachability", "delivered", "leg",
];
const hits = (text: string) =>
  FORBIDDEN.filter((w) => new RegExp(`(?<![\\w-])${w}(?![\\w-])`, "i").test(text));

describe("result vocabulary", () => {
  it("shows no word outside the result vocabulary", () => {
    const exits: EstateExit[] = [ZONE, WAN, { ...ZONE, basis: "access-client-default" }, { ...ZONE, site_block: null }];
    for (const reach of ["left_estate", "split"] as const) {
      const result = { ...edge(reach), legs: exits.map((exit, lane) => ({ ...FIXTURE_PATH_SINGLE.legs[0], lane, left_estate: exit })) };
      const { container, unmount } = pane(result);
      const text = container.querySelector(".trace-reach")?.textContent ?? "";
      expect(text).not.toBe("");
      expect(hits(text)).toEqual([]);
      unmount();
    }
    for (const exit of exits) expect(hits(`left estate ${exitText(exit)}`)).toEqual([]);
  });
});
