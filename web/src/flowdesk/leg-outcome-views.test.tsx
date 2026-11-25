import { describe, it, expect } from "vitest";
import { render, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { PathGraphView } from "./PathGraphView";
import { PathTreeView } from "./PathTreeView";
import { Inspector } from "./Inspector";
import { TraceRender, type TraceViewMode } from "./TraceGroups";
import { stationVerdict } from "./hopStyle";
import { allLegsBlocked, legWord } from "./verdict";
import { buildScene, sceneLanes } from "./strata/scene";
import { FIXTURE_PATH_SINGLE } from "../test/fixtures";
import type { Leg, PathResponse } from "../api/types";

function withAnswer(answer: "true" | "false" | "open", word: string, extra: Partial<Leg> = {}): PathResponse {
  const leg = FIXTURE_PATH_SINGLE.legs[0];
  return {
    ...FIXTURE_PATH_SINGLE,
    result: { ...FIXTURE_PATH_SINGLE.result, answer, word },
    legs: [{ ...leg, blocked: false, ...extra, result: { ...leg.result, answer, word } }],
  };
}

const NO_ROUTE = withAnswer("false", "no route found");
const OPEN = withAnswer("open", "open");

function wrap(node: React.ReactNode) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("leg helpers", () => {
  it("names a leg's word from the walk, or from its outcome when the walk has none", () => {
    expect(legWord(NO_ROUTE.legs[0])).toBe("no route found");
    expect(legWord(withAnswer("open", "").legs[0])).toBe("not decided");
  });
  it("counts a trace as all blocked only when a rulebase blocked every leg, not for no route", () => {
    expect(allLegsBlocked(NO_ROUTE.legs)).toBe(false);
    expect(allLegsBlocked(OPEN.legs)).toBe(false);
    expect(allLegsBlocked([{ ...NO_ROUTE.legs[0], blocked: true }])).toBe(true);
    expect(allLegsBlocked(FIXTURE_PATH_SINGLE.legs)).toBe(false);
    expect(allLegsBlocked([])).toBe(false);
  });
});

describe("Graph lane word", () => {
  it("draws the walk's word under the last box of a no-route lane, and in its path pill", () => {
    const { container, unmount } = render(<PathGraphView result={NO_ROUTE} selection={null} onSelect={() => {}} />);
    expect(container.querySelector(".pg-end.bad")?.textContent).toBe("no route found");
    expect(container.querySelector(".pg-pill.bad")?.textContent).toBe("no route found");
    unmount();
    const ok = render(<PathGraphView result={FIXTURE_PATH_SINGLE} selection={null} onSelect={() => {}} />);
    expect(ok.container.querySelector(".pg-end.bad, .pg-end.warn")).toBeNull();
    expect(ok.container.querySelector(".pg-pill.ok")).not.toBeNull();
  });
  it("draws a warn word for an undecided lane", () => {
    const { container } = render(<PathGraphView result={OPEN} selection={null} onSelect={() => {}} />);
    expect(container.querySelector(".pg-end.warn")?.textContent).toContain("open");
  });
  it("dashes a link that only blocked lanes use", () => {
    const { container } = render(<PathGraphView result={NO_ROUTE} selection={null} onSelect={() => {}} />);
    const links = container.querySelectorAll(".pg-link");
    expect(links.length).toBeGreaterThan(0);
    for (const link of links) expect(link.classList).toContain("blocked");
  });
});

describe("Tree lane word", () => {
  it("ends a no-route lane in a bad pill, an undecided one in a warn pill, a forwarded one in an ok pill", () => {
    const bad = render(<PathTreeView result={NO_ROUTE} selection={null} onSelect={() => {}} />);
    expect(bad.container.querySelector(".pt-end .pt-pill.bad")?.textContent).toBe("no route found");
    bad.unmount();
    const warn = render(<PathTreeView result={OPEN} selection={null} onSelect={() => {}} />);
    expect(warn.container.querySelector(".pt-end .pt-pill.warn")).not.toBeNull();
    warn.unmount();
    const ok = render(<PathTreeView result={FIXTURE_PATH_SINGLE} selection={null} onSelect={() => {}} />);
    expect(ok.container.querySelector(".pt-end .pt-pill.ok")).not.toBeNull();
  });
});

describe("shared gate in a trace whose every leg has no route", () => {
  const gate = { uid: "fwrb:shared", kind: "FwRulebase", shared: true };
  it("stays without a verdict when no rulebase denied a no-route leg", () => {
    expect(stationVerdict(gate, undefined, allLegsBlocked(NO_ROUTE.legs))).toBeNull();
    expect(stationVerdict(gate, undefined, allLegsBlocked([{ ...NO_ROUTE.legs[0], blocked: true }]))).toBe("bad");
  });
  it("stays without a verdict in the 3D scene as well", () => {
    const hops = [
      ...NO_ROUTE.hops,
      { uid: "fwrb:shared", kind: "FwRulebase", label: "shared", note: "", rank: 8, lane: 0, shared: true },
    ];
    const scene = buildScene({ hops, legs: NO_ROUTE.legs });
    expect(scene.nodes.find((n) => n.uid === "fwrb:shared")?.verdict).toBeNull();
    const denied = buildScene({ hops, legs: [{ ...NO_ROUTE.legs[0], blocked: true }] });
    expect(denied.nodes.find((n) => n.uid === "fwrb:shared")?.verdict).toBe("bad");
    expect(buildScene({ hops, legs: FIXTURE_PATH_SINGLE.legs }).nodes.find((n) => n.uid === "fwrb:shared")?.verdict).toBeNull();
  });
  it("leaves the rulebase chip on its own verdict: the rulebase permitted, the lane word says no route", () => {
    const leg = { ...NO_ROUTE.legs[0], fw_uid: "fwrb:shared" };
    expect(stationVerdict(gate, leg, false)).toBe("ok");
  });
});

describe("3D lane words", () => {
  it("lists the lanes that are not forwarded or not decided, with the walk's word", () => {
    expect(sceneLanes(NO_ROUTE.legs)).toEqual([
      expect.objectContaining({ lane: 0, outcome: "bad", word: "no route found" }),
    ]);
    expect(sceneLanes(OPEN.legs)[0]).toEqual(expect.objectContaining({ outcome: "warn", word: "open" }));
    expect(sceneLanes(FIXTURE_PATH_SINGLE.legs)).toEqual([]);
  });
});

describe("Inspector leg", () => {
  it("lists not decided for an open leg that no gate flagged, and colours a no-route leg bad", () => {
    const open = wrap(
      <Inspector selection={{ type: "leg", data: OPEN.legs[0] }} result={OPEN} open onToggle={() => {}} />,
    );
    expect(open.container.textContent).toContain("not decided");
    open.unmount();
    const bad = wrap(
      <Inspector selection={{ type: "leg", data: NO_ROUTE.legs[0] }} result={NO_ROUTE} open onToggle={() => {}} />,
    );
    expect(bad.container.innerHTML).toContain("var(--bad)");
    expect(bad.container.innerHTML).not.toContain("var(--ok)");
  });
});

describe("the verdict line of a pane", () => {
  function pane(result: PathResponse, view: TraceViewMode = "graph") {
    return wrap(<TraceRender view={view} result={result} selection={null} onSelect={() => {}} />);
  }
  it("states a no-route walk and an undecided walk above the view", () => {
    const bad = pane(NO_ROUTE);
    expect(bad.container.querySelector(".banner.warn[role='status']")?.textContent).toContain("no route found");
    bad.unmount();
    const open = pane(OPEN);
    expect(open.container.querySelector(".banner.warn")?.textContent).toContain("open");
  });
  it("is absent for a forwarded walk, and for a result with no hops", () => {
    const ok = pane(FIXTURE_PATH_SINGLE);
    expect(ok.container.querySelector(".banner")).toBeNull();
    ok.unmount();
    const empty = pane({ ...NO_ROUTE, hops: [] });
    expect(empty.container.querySelector(".banner")).toBeNull();
  });
  it("is drawn in every view", () => {
    for (const view of ["graph", "tree"] as const) {
      const { container, unmount } = pane(NO_ROUTE, view);
      expect(within(container).getByRole("status").textContent).toContain("no route found");
      unmount();
    }
  });
});

describe("pane banner, path detail and the inspector", () => {
  it("states a pane's own legs, not the whole trace's answer", () => {
    // an interpretation pane whose lane forwards, cut from a trace that has no route elsewhere
    const pane = { ...NO_ROUTE, legs: FIXTURE_PATH_SINGLE.legs };
    const { container } = wrap(
      <TraceRender view="graph" result={pane} selection={null} onSelect={() => {}} />,
    );
    expect(container.querySelector(".banner.warn")).toBeNull();
  });
  it("states a no-route leg of the pane with its own detail", () => {
    const { container } = wrap(
      <TraceRender view="graph" result={NO_ROUTE} selection={null} onSelect={() => {}} />,
    );
    const banner = container.querySelector(".banner.warn");
    expect(banner?.textContent).toContain("no route found");
    expect(banner?.textContent).toContain(NO_ROUTE.legs[0].detail.slice(0, 10));
  });
  it("keeps the leg's detail on its path pill", () => {
    const { container } = render(<PathGraphView result={NO_ROUTE} selection={null} onSelect={() => {}} />);
    expect(container.querySelector(".pg-pill.bad")?.getAttribute("title")).toBe(NO_ROUTE.legs[0].detail);
  });
  it("says not decided for a leg that is both blocked and undecided", () => {
    const leg = { ...NO_ROUTE.legs[0], blocked: true, indeterminate: true };
    const result = { ...NO_ROUTE, legs: [leg] };
    const { container } = wrap(
      <Inspector selection={{ type: "leg", data: leg }} result={result} open onToggle={() => {}} />,
    );
    expect(container.textContent).toContain("not decided");
  });
});
