/**
 * The estate on the world map. What the model holds (the majors, the homes,
 * the badges, the rings) is asserted in backbone.test.ts, and the fit, the
 * spread and the label collisions in estate.test.ts; this file asserts what
 * the SVG draws, the clicks on it, and the text alternative. jsdom has no
 * ResizeObserver, so the map keeps its default size of 1000 by 500 px.
 */

import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import type { SiteGraphPayload } from "../api/types";
import { project } from "../diagram/projection";
import type { View } from "../diagram/useCanvas";
import EstateMap, { type Group } from "./EstateMap";
import { majorsOf } from "./backbone";
import { DEFAULT_KINDS, fitView, SPREAD_PX } from "./estate";
import { edge, PAYLOAD, site } from "./fixture";

/** The map with the page's selection and badge state, and spies for the rest. */
function renderMap(payload: SiteGraphPayload = PAYLOAD, opts: { view?: View; expanded?: Group[] } = {}) {
  const onOpen = vi.fn();
  const onList = vi.fn();
  const onView = vi.fn();
  function Page() {
    const [selected, setSelected] = useState<string | null>(null);
    const [expanded, setExpanded] = useState<Group[]>(opts.expanded ?? []);
    return (
      <EstateMap
        payload={payload}
        kinds={DEFAULT_KINDS}
        selected={selected}
        onSelect={setSelected}
        onOpen={onOpen}
        expanded={expanded}
        onExpanded={setExpanded}
        onList={onList}
        initialView={opts.view}
        onView={onView}
      />
    );
  }
  const { container } = render(<Page />);
  const svg = container.querySelector("svg.nm-estate") as SVGSVGElement;
  const el = (kind: string, code = "") =>
    container.querySelector(`[data-marker="${kind}"][data-code="${code}"]`) as SVGGElement | null;
  const codes = (selector: string) =>
    [...container.querySelectorAll(selector)].map((n) => n.getAttribute("data-code") ?? "").sort();
  const at = (code: string) => {
    const m = /translate\(([-\d.e]+) ([-\d.e]+)\)/.exec(el("site", code)!.getAttribute("transform")!);
    return { x: Number(m![1]), y: Number(m![2]) };
  };
  return { container, svg, el, codes, at, onOpen, onList, onView };
}

const MAJORS = ["FR2", "ams-dc", "fra-hub1", "fra-hub2"];

describe("EstateMap", () => {
  it("draws the major sites only, one badge, the No hub pill and the line between major sites", () => {
    const { container, el, codes } = renderMap();
    expect(codes(".nm-major")).toEqual(MAJORS);
    expect(codes(".nm-branch")).toEqual([]);
    expect(el("badge", "fra-hub1")!.textContent).toBe("+2");
    expect(codes(".nm-badge")).toEqual(["fra-hub1"]);
    expect(el("nohub")!.textContent).toBe("No hub (2)");
    // BGP is not a counted kind by default, so ams-dc and fra-hub2 have no line
    expect([...container.querySelectorAll("[data-line]")].map((n) => n.getAttribute("data-line"))).toEqual([
      "FR2~fra-hub1",
    ]);
    expect(container.querySelector(".nm-land")).not.toBeNull();
  });

  it("shows a line's counts only on hover", () => {
    const { container } = renderMap();
    expect(container.querySelector(".nm-line-label")).toBeNull();
    fireEvent.pointerOver(container.querySelector('[data-line="FR2~fra-hub1"] .nm-hit')!);
    expect(container.querySelector(".nm-line-label")!.textContent).toBe("4 cables");
    fireEvent.pointerOut(container.querySelector('[data-line="FR2~fra-hub1"] .nm-hit')!);
    expect(container.querySelector(".nm-line-label")).toBeNull();
  });

  it("opens to the major sites when there is no kept camera", () => {
    const { svg } = renderMap();
    const points = majorsOf(PAYLOAD.sites)
      .filter((m) => m.site.lat !== null)
      .map((m) => project(m.site.lat as number, m.site.lon as number));
    const fit = fitView(points);
    expect(svg.getAttribute("viewBox")).toBe(`${fit.x} ${fit.y} ${fit.w} ${fit.h}`);
  });

  it("zooms with the buttons, and Fit returns to the major sites", async () => {
    const user = userEvent.setup();
    const { svg } = renderMap();
    const first = svg.getAttribute("viewBox");
    await user.click(screen.getByRole("button", { name: "Zoom in" }));
    expect(svg.getAttribute("viewBox")).not.toBe(first);
    await user.click(screen.getByRole("button", { name: "Fit" }));
    expect(svg.getAttribute("viewBox")).toBe(first);
  });

  it("spreads the major sites of one city apart, the same way on every render", () => {
    const one = renderMap();
    const view = one.svg.getAttribute("viewBox")!.split(" ").map(Number);
    const ppu = Math.min(1000 / view[2], 500 / view[3]);
    const frankfurt = ["FR2", "fra-hub1", "fra-hub2"].map(one.at);
    for (let i = 0; i < frankfurt.length; i++)
      for (let j = i + 1; j < frankfurt.length; j++) {
        const d = Math.hypot(frankfurt[i].x - frankfurt[j].x, frankfurt[i].y - frankfurt[j].y) * ppu;
        expect(d).toBeGreaterThanOrEqual(SPREAD_PX - 1e-6);
      }
    const first = MAJORS.map(one.at);
    one.container.remove();
    const two = renderMap();
    expect(MAJORS.map(two.at)).toEqual(first);
  });

  it("shows a badge's branches on a click with no major site moving, and hides them on a second click", () => {
    const { container, el, codes, at } = renderMap();
    const before = MAJORS.map(at);
    fireEvent.click(el("badge", "fra-hub1")!);
    expect(codes(".nm-branch")).toEqual(["ber-b1", "ber-b2"]);
    expect(container.querySelectorAll(".nm-branch-link")).toHaveLength(3);
    expect(MAJORS.map(at)).toEqual(before);
    expect(screen.getByRole("button", { name: "Show 2 branches of fra-hub1" })).toHaveAttribute("aria-expanded", "true");
    fireEvent.click(el("badge", "fra-hub1")!);
    expect(codes(".nm-branch")).toEqual([]);
    expect(container.querySelectorAll(".nm-branch-link")).toHaveLength(0);
    expect(MAJORS.map(at)).toEqual(before);
  });

  it("selects a site on a click and fades the rest; a second click or a double click opens it", () => {
    const { svg, el, onOpen } = renderMap();
    fireEvent.click(el("site", "fra-hub1")!);
    expect(el("site", "fra-hub1")).toHaveClass("selected");
    expect(el("site", "ams-dc")).toHaveClass("faded");
    expect(el("site", "fra-hub2")).toHaveClass("faded");
    // its own line, the far end and its badge stay
    expect(el("site", "FR2")).not.toHaveClass("faded");
    expect(el("badge", "fra-hub1")).not.toHaveClass("faded");
    expect(svg.querySelector('[data-line="FR2~fra-hub1"]')).toHaveClass("selected");
    expect(svg.querySelector(".nm-line-label")!.textContent).toBe("4 cables");
    expect(onOpen).not.toHaveBeenCalled();

    fireEvent.click(el("site", "fra-hub1")!);
    expect(onOpen).toHaveBeenCalledWith("fra-hub1");
    fireEvent.doubleClick(el("site", "ams-dc")!);
    expect(onOpen).toHaveBeenCalledWith("ams-dc");

    // a click on the background clears the selection
    fireEvent.click(svg);
    expect(el("site", "fra-hub1")).not.toHaveClass("selected");
    expect(el("site", "ams-dc")).not.toHaveClass("faded");
  });

  it("selects a shown branch", () => {
    const { el } = renderMap();
    fireEvent.click(el("badge", "fra-hub1")!);
    fireEvent.click(el("site", "ber-b1")!);
    expect(el("site", "ber-b1")).toHaveClass("selected");
    expect(screen.getByRole("button", { name: "ber-b1, branch" })).toHaveAttribute("aria-pressed", "true");
  });

  it("shows the No hub ring and lists its branches in the side panel", () => {
    const { el, codes, onList } = renderMap();
    fireEvent.click(el("nohub")!);
    expect(codes(".nm-branch")).toEqual(["muc-b1", "nowhere"]);
    expect(onList).toHaveBeenCalledWith(null);
    fireEvent.click(el("nohub")!);
    expect(codes(".nm-branch")).toEqual([]);
    expect(onList).toHaveBeenLastCalledWith(undefined);
  });

  it("ends a ring of more than 120 branches in an and-more pill that opens the list", () => {
    const branches = Array.from({ length: 130 }, (_, i) => `b${String(i).padStart(3, "0")}`);
    const payload: SiteGraphPayload = {
      sites: [site("hub", 50, 8, { tiers: { "sdwan-hub": 2 } }), ...branches.map((code) => site(code, null, null))],
      edges: branches.map((code) => edge(code, "hub", "tunnel")),
      unplaced: [],
    };
    const { el, codes, onList } = renderMap(payload);
    fireEvent.click(el("badge", "hub")!);
    expect(codes(".nm-branch")).toHaveLength(119);
    expect(el("more", "hub")!.textContent).toBe("11 more");
    fireEvent.click(el("more", "hub")!);
    expect(onList).toHaveBeenCalledWith("hub");
  });

  it("lists the major sites with no coordinates beside the map, draws none of their lines, and selects them", async () => {
    const user = userEvent.setup();
    const payload: SiteGraphPayload = {
      ...PAYLOAD,
      sites: [...PAYLOAD.sites, site("lon-dc", null, null, { kind: "dc" }), site("lon-b1", null, null)],
      edges: [...PAYLOAD.edges, edge("lon-dc", "fra-hub1", "circuit", 2), edge("lon-b1", "lon-dc", "tunnel")],
    };
    const { container, el, onOpen } = renderMap(payload);
    expect(el("site", "lon-dc")).toBeNull();
    expect(el("badge", "lon-dc")).toBeNull();
    expect(container.querySelector('[data-line="fra-hub1~lon-dc"]')).toBeNull();
    const list = screen.getByRole("region", { name: "Not on the map" });
    expect(within(list).getByText("data center, 1 branch")).toBeInTheDocument();
    expect(within(list).queryByText("lon-b1")).not.toBeInTheDocument();
    const row = within(list).getByRole("button", { name: "lon-dc" });
    await user.click(row);
    expect(row).toHaveAttribute("aria-pressed", "true");
    await user.click(row);
    expect(onOpen).toHaveBeenCalledWith("lon-dc");
  });

  it("restores the kept camera and open badges, and ignores a code that is no longer a major site", () => {
    const view = { x: 700, y: 140, w: 100, h: 50 };
    const { svg, codes, onView } = renderMap(PAYLOAD, { view, expanded: ["gone", "fra-hub1"] });
    expect(svg.getAttribute("viewBox")).toBe("700 140 100 50");
    expect(codes(".nm-branch")).toEqual(["ber-b1", "ber-b2"]);
    expect(onView).toHaveBeenLastCalledWith(view);
  });

  it("carries the same actions as a list", async () => {
    const user = userEvent.setup();
    const { el, codes } = renderMap();
    const list = screen.getByRole("region", { name: "Estate list" });
    expect(within(list).getByRole("button", { name: "ams-dc, data center" })).toBeInTheDocument();
    expect(within(list).getByRole("button", { name: "FR2, colocation" })).toBeInTheDocument();
    expect(within(list).getByText("FR2 to fra-hub1: 4 cables")).toBeInTheDocument();
    expect(within(list).getByRole("button", { name: "Show 2 branches with no hub" })).toHaveAttribute("aria-expanded", "false");
    const show = within(list).getByRole("button", { name: "Show 2 branches of fra-hub1" });
    await user.click(show);
    expect(show).toHaveAttribute("aria-expanded", "true");
    expect(codes(".nm-branch")).toEqual(["ber-b1", "ber-b2"]);
    await user.click(within(list).getByRole("button", { name: "fra-hub1, SD-WAN hub" }));
    expect(el("site", "fra-hub1")).toHaveClass("selected");
  });
});
