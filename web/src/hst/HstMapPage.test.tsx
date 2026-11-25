import { describe, expect, it } from "vitest";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import HstMapPage, { type RendererFactory } from "./HstMapPage";
import type { Source, Timeline } from "./data/api";
import { toScreen } from "./render/camera";
import { Y } from "./render/scene";
import { createNullRenderer, type NullRenderer } from "./render/null";
import { FakeSource, history } from "./test/runs";
import type { EventStream } from "./timeline/events";

function nullFactory(): { factory: RendererFactory; get: () => NullRenderer } {
  let r: NullRenderer | null = null;
  return {
    factory: async () => (r = createNullRenderer()),
    get: () => r!,
  };
}

function empty(): Source {
  const source = new FakeSource([]);
  source.timeline = async (): Promise<Timeline> => ({ current: null, runs: [] });
  return source;
}

describe("HstMapPage", () => {
  it("renders the heading and the empty state", async () => {
    render(<HstMapPage source={empty()} renderer={nullFactory().factory} events={null} />);
    expect(screen.getByRole("heading", { name: "Hyperspatial Twin" })).toBeInTheDocument();
    expect(await screen.findByText("No run loaded")).toBeInTheDocument();
  });

  it("opens at Now and states History after a step back", async () => {
    const states = history(6);
    const r = nullFactory();
    render(<HstMapPage source={new FakeSource(states)} renderer={r.factory} events={null} />);
    expect(await screen.findByRole("status")).toHaveTextContent("Now");
    expect([...r.get().scene.rows("render_t1")]).toHaveLength(states[5].render_t1.length);
    fireEvent.click(screen.getByRole("button", { name: "Step back" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent(/^History: /));
    fireEvent.click(screen.getByRole("button", { name: "Now" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Now"));
  });

  it("gives the page theme to a renderer that finishes loading after the theme was read", async () => {
    const root = document.documentElement;
    root.style.setProperty("--bg", "#101010");
    try {
      const r = nullFactory();
      render(<HstMapPage source={new FakeSource(history(3))} renderer={r.factory} events={null} />);
      await screen.findByRole("status");
      expect(r.get().scene.style.theme).toBe("dark");
    } finally {
      root.style.removeProperty("--bg");
    }
  });

  it("opens with the estate tree hidden and shows it on request", async () => {
    render(<HstMapPage source={new FakeSource(history(3))} renderer={nullFactory().factory} events={null} />);
    await screen.findByRole("status");
    expect(screen.queryByRole("navigation", { name: "Estate" })).toBeNull();
    fireEvent.click(document.querySelector<HTMLButtonElement>(".hst-tree-open")!);
    expect(await screen.findByRole("navigation", { name: "Estate" })).toBeInTheDocument();
  });

  it("finds a device, selects it and shows it in the breadcrumb", async () => {
    const r = nullFactory();
    render(<HstMapPage source={new FakeSource(history(3))} renderer={r.factory} events={null} />);
    await screen.findByRole("status");
    fireEvent.change(screen.getByRole("searchbox", { name: "Search the map" }), { target: { value: "s1d7" } });
    fireEvent.click(within(screen.getByRole("list", { name: "Search results" })).getByRole("button", { name: /s1d7/ }));
    const crumbs = within(screen.getByRole("navigation", { name: "Breadcrumb" }));
    await waitFor(() => expect(crumbs.getByText("s1d7")).toBeInTheDocument());
    expect(crumbs.getByRole("button", { name: "s1" })).toBeInTheDocument();
    await waitFor(() => expect(r.get().scene.style.selected).toBe("dev:s1d7"));
  });

  it("filters by context and toggles the change layer", async () => {
    const r = nullFactory();
    render(<HstMapPage source={new FakeSource(history(3))} renderer={r.factory} events={null} />);
    await screen.findByRole("status");
    const select = screen.getByRole("combobox", { name: "Context" });
    expect(within(select).getByRole("option", { name: "blue (65000:1)" })).toBeInTheDocument();
    fireEvent.change(select, { target: { value: "ident:blue:s1" } });
    await waitFor(() => expect(r.get().scene.style.context).toBe("ident:blue:s1"));
    expect(r.get().scene.batches(1).boxes.find((b) => b.cls === "plate")?.ids).toEqual(["plate:s1"]);
    fireEvent.click(screen.getByRole("checkbox", { name: "Changes since previous run" }));
    await waitFor(() => expect(r.get().scene.style.changes).toBe(true));
  });

  it("shows the new-run pill when the event stream reports a run", async () => {
    const states = history(5);
    const source = new FakeSource(states);
    const shown = new FakeSource(states.slice(0, 4));
    const later = source.timeline.bind(source);
    let first = true;
    source.timeline = async () => {
      if (!first) return later();
      first = false;
      return shown.timeline();
    };
    let ready: ((e: MessageEvent) => void) | null = null;
    const stream: EventStream = {
      addEventListener: (type, fn) => {
        if (type === "run.tiers_ready") ready = fn;
      },
      close: () => {},
    };
    render(<HstMapPage source={source} renderer={nullFactory().factory} events={() => stream} />);
    await screen.findByRole("status");
    expect(screen.queryByRole("button", { name: "New run ready" })).toBeNull();
    await act(async () => ready!(new MessageEvent("run.tiers_ready", { data: JSON.stringify({ run_key: source.keys[4] }) })));
    fireEvent.click(await screen.findByRole("button", { name: "New run ready" }));
    await waitFor(() => expect(screen.queryByRole("button", { name: "New run ready" })).toBeNull());
    expect(screen.getByRole("status")).toHaveTextContent("Now");
  });
});

describe("HstMapPage directions", () => {
  it("draws a handed-over trace as a route with pins and a step list, and Close clears it", async () => {
    const hop = (uid: string, kind: string, rank: number) => ({ uid, kind, label: uid.split("/").pop() ?? uid, note: "", rank, lane: 0, shared: true });
    const result = {
      detail: "forwarded",
      notes: [],
      hops: [hop("dev:s0d0", "Device", 0), hop("dev:s0d1", "Device", 1), hop("ep:far", "Endpoint", 2)],
      legs: [],
    } as unknown as import("../api/types").PathResponse;
    const r = nullFactory();
    render(<HstMapPage source={new FakeSource(history(3))} renderer={r.factory} events={null} trace={{ result, snapshot: null }} />);
    const steps = await screen.findByRole("complementary", { name: "Directions" });
    expect(within(steps).getAllByRole("listitem")).toHaveLength(3);
    await waitFor(() => expect(r.get().frame().markers.map((m) => m.kind)).toEqual(["start", "end"]));
    expect(screen.queryByRole("tree")).toBeNull();
    fireEvent.click(within(steps).getByRole("button", { name: /^1dev:s0d1/ }));
    await waitFor(() => expect(screen.getByRole("complementary", { name: "s0d1 details" })).toBeTruthy());
    fireEvent.click(within(steps).getByRole("button", { name: "Close" }));
    await waitFor(() => expect(r.get().frame().markers).toEqual([]));
    expect(screen.queryByRole("complementary", { name: "Directions" })).toBeNull();
  });
});

describe("HstMapPage selection", () => {
  it("loads the tile of the selected device so its port names show at every zoom", async () => {
    const r = nullFactory();
    render(<HstMapPage source={new FakeSource(history(3))} renderer={r.factory} events={null} />);
    await screen.findByRole("status");
    fireEvent.change(screen.getByRole("searchbox", { name: "Search the map" }), { target: { value: "s1d3" } });
    fireEvent.keyDown(screen.getByRole("searchbox", { name: "Search the map" }), { key: "Enter" });
    await waitFor(() => expect(r.get().scene.row("render_t2_ports", "dev:s1d3/port/eth0")).toBeDefined());
    expect(r.get().scene.tiles()).toEqual(new Set(["block:s1:campus"]));
  });

  it("opens the cable modal with both sides on a click on a cable", async () => {
    const r = nullFactory();
    render(<HstMapPage source={new FakeSource(history(3))} renderer={r.factory} events={null} />);
    await screen.findByRole("status");
    fireEvent.change(screen.getByRole("searchbox", { name: "Search the map" }), { target: { value: "s1d3" } });
    fireEvent.keyDown(screen.getByRole("searchbox", { name: "Search the map" }), { key: "Enter" });
    await waitFor(() => expect(r.get().frame().level).toBe(4), { timeout: 2000 });
    await waitFor(() => expect(r.get().scene.batches(4).lines.some((l) => l.cls === "cable")).toBe(true));
    const { camera, viewport, scene } = r.get();
    const cable = scene.batches(4).lines.find((l) => l.cls === "cable")!;
    const p = cable.positions;
    const [x, y] = toScreen(camera, viewport, (p[0] + p[3]) / 2, (p[2] + p[5]) / 2, p[1]);
    const canvas = screen.getByRole("application", { name: "Map canvas" });
    fireEvent.pointerDown(canvas, { clientX: x, clientY: y });
    fireEvent.pointerUp(canvas, { clientX: x, clientY: y });
    const modal = await screen.findByRole("region", { name: "Cable configuration" });
    expect(await within(modal).findByLabelText("A side")).toBeTruthy();
    expect(within(modal).getByLabelText("B side")).toBeTruthy();
    fireEvent.keyDown(canvas, { key: "Escape" });
    expect(screen.queryByRole("region", { name: "Cable configuration" })).toBeNull();
  });

  it("switches between the 2D and 3D views and opens the panel of a found device", async () => {
    const r = nullFactory();
    render(<HstMapPage source={new FakeSource(history(3))} renderer={r.factory} events={null} />);
    await screen.findByRole("status");
    const controls = screen.getByRole("toolbar", { name: "Map controls" });
    fireEvent.click(within(controls).getByRole("button", { name: "2D" }));
    await waitFor(() => expect(r.get().camera.view).toBe("top"));
    expect(within(controls).getByRole("button", { name: "2D" }).getAttribute("aria-pressed")).toBe("true");
    fireEvent.click(within(controls).getByRole("button", { name: "3D" }));
    await waitFor(() => expect(r.get().camera.view).toBe("iso"));
    const zoom = r.get().camera.zoom;
    fireEvent.click(within(controls).getByRole("button", { name: "Zoom in" }));
    await waitFor(() => expect(r.get().camera.zoom).toBeGreaterThan(zoom));
    fireEvent.change(screen.getByRole("searchbox", { name: "Search the map" }), { target: { value: "s1d3" } });
    fireEvent.keyDown(screen.getByRole("searchbox", { name: "Search the map" }), { key: "Enter" });
    const panel = await screen.findByRole("complementary", { name: "s1d3 details" });
    fireEvent.click(within(panel).getByRole("tab", { name: /Links/ }));
    expect(within(panel).getAllByRole("button").length).toBeGreaterThan(1);
    fireEvent.click(within(panel).getByRole("button", { name: "Close the details" }));
    expect(screen.queryByRole("complementary", { name: "s1d3 details" })).toBeNull();
  });

  it("opens the cable modal, not the interface overlay, on a click on a cabled port", async () => {
    const r = nullFactory();
    render(<HstMapPage source={new FakeSource(history(3))} renderer={r.factory} events={null} />);
    await screen.findByRole("status");
    fireEvent.change(screen.getByRole("searchbox", { name: "Search the map" }), { target: { value: "s1d3" } });
    fireEvent.keyDown(screen.getByRole("searchbox", { name: "Search the map" }), { key: "Enter" });
    await waitFor(() => expect(r.get().frame().level).toBe(4), { timeout: 2000 });
    await waitFor(() => expect([...r.get().scene.rows("render_t2_cables")].length).toBeGreaterThan(0));
    const { camera, viewport, scene } = r.get();
    const cable = [...scene.rows("render_t2_cables")].find((c) => String(c.a_port).startsWith("dev:s1d3/") || String(c.b_port).startsWith("dev:s1d3/"))!;
    const port = scene.layout.get(String(String(cable.a_port).startsWith("dev:s1d3/") ? cable.a_port : cable.b_port))!;
    const [x, y] = toScreen(camera, viewport, port.u + port.w / 2, port.v + port.h / 2, Y.portTop);
    const canvas = screen.getByRole("application", { name: "Map canvas" });
    fireEvent.pointerDown(canvas, { clientX: x, clientY: y });
    fireEvent.pointerUp(canvas, { clientX: x, clientY: y });
    expect(await screen.findByRole("region", { name: "Cable configuration" })).toBeTruthy();
    expect(screen.queryByRole("region", { name: "Interface overlay" })).toBeNull();
  });
});
