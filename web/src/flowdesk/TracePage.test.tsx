import { describe, it, expect, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import TracePage from "./TracePage";
import { mockApi } from "../test/fetchMock";
import {
  FIXTURE_PATH_BLOCKED,
  FIXTURE_PATH_PARTITION,
  FIXTURE_PATH_SINGLE,
  FIXTURE_SNAPSHOTS,
} from "../test/fixtures";
import type { BidirectionalPathResponse, PathCompareResponse } from "../api/types";
import { AiContextProvider } from "../ai/context";
import { PageContextProbe, readPageContext } from "../test/aiContext";

function renderTracePage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <TracePage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

async function trace() {
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: /trace/i }));
  return user;
}

/** The body of a collapsed block is not in the DOM. */
async function expandBlock(user: ReturnType<typeof userEvent.setup>, root: HTMLElement) {
  await user.click(within(root).getByRole("button"));
}

describe("TracePage: trace mode wiring", () => {
  it("blocked fixture: the deciding rulebase is marked, and the inspector names it", async () => {
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
      "GET /api/path": () => ({ status: 200, body: FIXTURE_PATH_BLOCKED }),
    });
    renderTracePage();

    const user = await trace();

    // the graph carries the verdict, on the node that produced it
    await waitFor(() => expect(document.querySelector(".pg-verdict.bad")).not.toBeNull());
    const inspector = document.querySelector(".inspector") as HTMLElement;
    await expandBlock(user, inspector);
    expect(
      within(inspector).getByText("IOT-LAN (IOT→LAN) drop by default-action"),
    ).toBeInTheDocument();
  });

  it("blocked leg with no firewall named: the deciding chip is marked, with no cap text", async () => {
    const blockedNoFirewall = {
      ...FIXTURE_PATH_BLOCKED,
      legs: [{ ...FIXTURE_PATH_BLOCKED.legs[0], firewall: undefined }],
    };
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
      "GET /api/path": () => ({ status: 200, body: blockedNoFirewall }),
    });
    const { container } = renderTracePage();

    await trace();

    // the verdict lives on the rulebase node
    await waitFor(() => expect(container.querySelector(".pg-verdict.bad")).not.toBeNull());
  });

  it("partition fixture: lane caps carry no caption and no address slice", async () => {
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
      "GET /api/path": () => ({ status: 200, body: FIXTURE_PATH_PARTITION }),
    });
    const { container } = renderTracePage();

    const user = await trace();

    await waitFor(() => expect(document.querySelector(".pg-box")).not.toBeNull());
    expect(screen.queryAllByRole("button", { name: /^Permitted:/ })).toHaveLength(0);
    expect(screen.queryByText("permitted")).not.toBeInTheDocument();
    const inspector = document.querySelector(".inspector") as HTMLElement;
    await expandBlock(user, inspector);
    expect(within(inspector).getByText(/leg \d/)).toBeInTheDocument();

    const svg = container.querySelector(".pg-svg") as unknown as HTMLElement;
    expect(within(svg).queryByText("192.168.10.43/32, 192.168.10.44/31")).not.toBeInTheDocument();
    expect(within(svg).queryByText(/\+1 more \(251 addresses\)/)).not.toBeInTheDocument();
    expect(within(svg).queryByText(/egress via/)).not.toBeInTheDocument();
    expect(within(inspector).getByText("192.168.10.43/32, 192.168.10.44/31")).toBeInTheDocument();
  });

  it("a station click fills the node details panel and opens no dialog", async () => {
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
      "GET /api/path": () => ({ status: 200, body: FIXTURE_PATH_SINGLE }),
    });
    renderTracePage();
    const user = await trace();

    const hop = FIXTURE_PATH_SINGLE.hops[2];
    await user.click(await screen.findByRole("button", { name: `${hop.label}, ${hop.kind}, path 1` }));

    expect(await screen.findByText(`uid ${hop.uid}`)).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("draws no verdict banner for a successful trace", async () => {
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
      "GET /api/path": () => ({ status: 200, body: FIXTURE_PATH_PARTITION }),
    });
    const { container } = renderTracePage();

    await trace();
    await waitFor(() => expect(container.querySelector(".pg-svg")).not.toBeNull());

    expect(screen.queryByText("PERMITTED")).not.toBeInTheDocument();
    expect(
      screen.queryByText(`${FIXTURE_PATH_PARTITION.legs.length} paths`),
    ).not.toBeInTheDocument();
    expect(container.querySelector(".banner")).toBeNull();
  });

  it("clicking a station fills the inspector with its uid, overriding the default", async () => {
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
      "GET /api/path": () => ({ status: 200, body: FIXTURE_PATH_SINGLE }),
    });
    renderTracePage();

    const user = await trace();
    const inspector = document.querySelector(".inspector") as HTMLElement;

    // FIXTURE_PATH_SINGLE has no gate-kind hop.
    await screen.findByRole("button", { name: "host44, Endpoint, path 1" });
    await expandBlock(user, inspector);
    expect(within(inspector).getByText("uid ep:host44")).toBeInTheDocument();

    const station = screen.getByRole("button", { name: "eth0.1, Interface, path 1" });
    await user.click(station);

    expect(within(inspector).getByText("uid if:core1/eth0.1")).toBeInTheDocument();
    expect(within(inspector).queryByText("uid ep:host44")).not.toBeInTheDocument();
  });

  it("defaults the inspector to the gate station when one exists, before any click", async () => {
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
      "GET /api/path": () => ({ status: 200, body: FIXTURE_PATH_BLOCKED }),
    });
    renderTracePage();

    const user = await trace();
    // wait for the graph: the deciding rulebase is marked in place
    await waitFor(() => expect(document.querySelector(".pg-verdict.bad")).not.toBeNull());

    const inspector = document.querySelector(".inspector") as HTMLElement;
    await expandBlock(user, inspector);
    expect(within(inspector).getByText("uid fwrb:IOT-LAN")).toBeInTheDocument();
  });
});

describe("TracePage: page context", () => {
  it("registers the submitted flow, the run it was traced on and the clicked station", async () => {
    const run = {
      snapshot: "1724236800000",
      created: null,
      degraded: false,
      sources_carried: [],
      sources_failed: [],
      sources_partial: [],
      sources_cancelled: [],
    };
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
      "GET /api/path": () => ({ status: 200, body: { ...FIXTURE_PATH_SINGLE, run } }),
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <AiContextProvider>
            <TracePage />
            <PageContextProbe />
          </AiContextProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    // nothing is traced yet, so the composer's defaults are not sent
    expect(readPageContext().flow).toBeUndefined();

    const user = await trace();
    await waitFor(() =>
      expect(readPageContext().flow).toEqual({
        src: "192.168.10.0/24",
        dst: "8.8.8.8",
        port: "443",
        proto: "tcp",
        reply: false,
      }),
    );
    expect(readPageContext().snapshot).toEqual({ id: "1724236800000", origin: "page-default" });

    await user.click(await screen.findByRole("button", { name: "eth0.1, Interface, path 1" }));
    await waitFor(() =>
      expect(readPageContext().selection).toEqual([
        { kind: "hop", uid: "if:core1/eth0.1", label: "eth0.1", source: "selection" },
      ]),
    );
  });
});

describe("TracePage: Info section", () => {
  it("surfaces what the engine could not prove, ahead of routine notes", async () => {
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
      "GET /api/path": () => ({
        status: 200,
        body: {
          ...FIXTURE_PATH_SINGLE,
          notes: ["src segment: l2seg:home:vlan110", "nat-source: on path, not evaluated"],
          warnings: ["nat-source: on path, not evaluated"],
        },
      }),
    });
    const { container } = renderTracePage();

    const user = await trace();

    const info = await screen.findByText("Info");
    const traceinfo = info.closest(".traceinfo") as HTMLElement;
    await expandBlock(user, traceinfo);
    const list = traceinfo.querySelector("ul")!;
    expect(list.children[0].textContent).toContain("nat-source: on path, not evaluated");
    expect(list.children[0]).toHaveClass("warn");
    expect(list.querySelectorAll("li")).toHaveLength(2);
    expect(container.querySelector(".banner")).toBeNull();
    expect(screen.queryByText("PERMITTED")).not.toBeInTheDocument();
  });

  it("renders nothing when the engine had nothing to add", async () => {
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
      "GET /api/path": () => ({
        status: 200,
        body: { ...FIXTURE_PATH_SINGLE, notes: [], warnings: [] },
      }),
    });
    const { container } = renderTracePage();

    await trace();
    await waitFor(() => expect(container.querySelector(".pg-svg")).not.toBeNull());

    expect(screen.queryByText("Info")).not.toBeInTheDocument();
  });
});

describe("TracePage: interpretation grouping", () => {
  it("more than one distinct interpretation renders a heading per group", async () => {
    const multi = {
      ...FIXTURE_PATH_PARTITION,
      legs: [
        {
          ...FIXTURE_PATH_PARTITION.legs[0],
          interpretation: { src_ip: "192.168.10.43", anchor: "vrf:dev:core1:table100", display: "table100" },
        },
        {
          ...FIXTURE_PATH_PARTITION.legs[1],
          interpretation: { src_ip: "192.168.10.43", anchor: "vrf:dev:core1:default", display: "default" },
        },
      ],
    };
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
      "GET /api/path": () => ({ status: 200, body: multi }),
    });
    const { container } = renderTracePage();

    await trace();

    expect(await screen.findByText("Assuming 192.168.10.43 in table100")).toBeInTheDocument();
    expect(screen.getByText("Assuming 192.168.10.43 in default")).toBeInTheDocument();
    // one Graph per interpretation, each framed on just its own lane
    expect(container.querySelectorAll(".pg-svg")).toHaveLength(2);
  });

  it("a single interpretation (or no interpretation field at all) renders no heading", async () => {
    // FIXTURE_PATH_PARTITION has no `interpretation` on either leg.
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
      "GET /api/path": () => ({ status: 200, body: FIXTURE_PATH_PARTITION }),
    });
    const { container } = renderTracePage();

    await trace();
    await waitFor(() => expect(container.querySelector(".pg-svg")).not.toBeNull());

    expect(screen.queryByText(/^Assuming /)).not.toBeInTheDocument();
    expect(container.querySelector(".trace-groups")).toBeNull();
    expect(container.querySelectorAll(".pg-svg")).toHaveLength(1);
  });
});

/** jsdom runs this suite on an opaque origin without `window.localStorage`. */
function installStorage(): void {
  const data = new Map<string, string>();
  Object.defineProperty(window, "localStorage", {
    configurable: true,
    value: {
      getItem: (k: string) => data.get(k) ?? null,
      setItem: (k: string, v: string) => void data.set(k, v),
      removeItem: (k: string) => void data.delete(k),
      clear: () => data.clear(),
    },
  });
}

/** jsdom gives every element a zero rect. */
describe("TracePage: details block resize", () => {
  beforeEach(installStorage);

  function bottom(container: HTMLElement): HTMLElement {
    return container.querySelector(".trace-bottom") as HTMLElement;
  }

  function stored(): unknown {
    const raw = window.localStorage.getItem("hst.trace.bottom");
    return raw === null ? undefined : JSON.parse(raw);
  }

  it("starts at its natural height, with nothing persisted", () => {
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
    });
    const { container } = renderTracePage();

    expect(bottom(container)).not.toBeNull();
    expect(bottom(container).style.height).toBe("");
    expect(stored()).toBeUndefined();
  });

  it("grows the block on ArrowUp and persists the height", async () => {
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
    });
    const user = userEvent.setup();
    const { container } = renderTracePage();

    const handle = screen.getByRole("separator", { name: "Resize trace details" });
    handle.focus();
    await user.keyboard("{ArrowUp}");

    expect(bottom(container).style.height).toBe("224px");
    expect(stored()).toBe(224);
  });

  it("shrinks on ArrowDown, no further than the floor", async () => {
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
    });
    const user = userEvent.setup();
    const { container } = renderTracePage();

    const handle = screen.getByRole("separator", { name: "Resize trace details" });
    handle.focus();
    for (let i = 0; i < 10; i++) await user.keyboard("{ArrowDown}");

    expect(bottom(container).style.height).toBe("80px");
    expect(stored()).toBe(80);
  });

  it("restores a persisted height", () => {
    window.localStorage.setItem("hst.trace.bottom", "300");
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
    });
    const { container } = renderTracePage();

    expect(bottom(container).style.height).toBe("300px");
  });

  it("double-click returns the block to its natural height", async () => {
    window.localStorage.setItem("hst.trace.bottom", "300");
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
    });
    const user = userEvent.setup();
    const { container } = renderTracePage();

    await user.dblClick(screen.getByRole("separator", { name: "Resize trace details" }));

    expect(bottom(container).style.height).toBe("");
    expect(stored()).toBeNull();
  });

  it("a drag on a zero-height page leaves the height alone", async () => {
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
    });
    const user = userEvent.setup();
    const { container } = renderTracePage();

    const handle = screen.getByRole("separator", { name: "Resize trace details" });
    await user.pointer([
      { target: handle, keys: "[MouseLeft>]", coords: { clientY: 400 } },
      { target: handle, coords: { clientY: 300 } },
      { target: handle, keys: "[/MouseLeft]" },
    ]);

    expect(bottom(container).style.height).toBe("");
  });
});

describe("TracePage: collapsible info and inspector blocks", () => {
  beforeEach(installStorage);

  // an expanded block also has a "raw evidence" or "N more" button
  function traceinfoHead(container: HTMLElement): HTMLElement {
    return container.querySelector(".traceinfo .tb-head") as HTMLElement;
  }

  function inspectorHead(container: HTMLElement): HTMLElement {
    return container.querySelector(".inspector .tb-head") as HTMLElement;
  }

  it("both blocks render collapsed by default, and a header click expands and persists the state", async () => {
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
      "GET /api/path": () => ({
        status: 200,
        body: { ...FIXTURE_PATH_SINGLE, notes: ["src segment: l2seg:home:vlan110"] },
      }),
    });
    const { container } = renderTracePage();
    const user = await trace();
    await waitFor(() => expect(container.querySelector(".pg-svg")).not.toBeNull());

    expect(traceinfoHead(container)).toHaveAttribute("aria-expanded", "false");
    expect(inspectorHead(container)).toHaveAttribute("aria-expanded", "false");
    expect(container.querySelector(".traceinfo ul")).toBeNull();
    expect(container.querySelector(".inspector .row")).toBeNull();

    await user.click(traceinfoHead(container));
    expect(traceinfoHead(container)).toHaveAttribute("aria-expanded", "true");
    expect(container.querySelector(".traceinfo ul")).not.toBeNull();
    expect(window.localStorage.getItem("hst.trace.info.open")).toBe("true");

    // closes again, and un-persists
    await user.click(traceinfoHead(container));
    expect(traceinfoHead(container)).toHaveAttribute("aria-expanded", "false");
    expect(window.localStorage.getItem("hst.trace.info.open")).toBe("false");
  });

  it("selecting a node expands the inspector", async () => {
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
      "GET /api/path": () => ({ status: 200, body: FIXTURE_PATH_SINGLE }),
    });
    const { container } = renderTracePage();
    const user = await trace();

    const station = await screen.findByRole("button", { name: "eth0.1, Interface, path 1" });
    expect(inspectorHead(container)).toHaveAttribute("aria-expanded", "false");

    await user.click(station);

    expect(inspectorHead(container)).toHaveAttribute("aria-expanded", "true");
    expect(window.localStorage.getItem("hst.trace.inspector.open")).toBe("true");
    expect(
      within(container.querySelector(".inspector") as HTMLElement).getByText("uid if:core1/eth0.1"),
    ).toBeInTheDocument();
  });

  it("a new trace collapses both blocks, even if the previous result left them open", async () => {
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
      "GET /api/path": () => ({
        status: 200,
        body: { ...FIXTURE_PATH_SINGLE, notes: ["src segment: l2seg:home:vlan110"] },
      }),
    });
    const { container } = renderTracePage();
    const user = await trace();
    await waitFor(() => expect(container.querySelector(".pg-svg")).not.toBeNull());

    await user.click(traceinfoHead(container));
    await user.click(inspectorHead(container));
    expect(traceinfoHead(container)).toHaveAttribute("aria-expanded", "true");
    expect(inspectorHead(container)).toHaveAttribute("aria-expanded", "true");

    await user.click(screen.getByRole("button", { name: /trace/i }));

    expect(traceinfoHead(container)).toHaveAttribute("aria-expanded", "false");
    expect(inspectorHead(container)).toHaveAttribute("aria-expanded", "false");
  });
});

describe("TracePage: snapshot compare", () => {
  function compareBody(): PathCompareResponse {
    return {
      a: { snapshot: FIXTURE_SNAPSHOTS.snapshots[0].id, result: FIXTURE_PATH_SINGLE },
      b: { snapshot: FIXTURE_SNAPSHOTS.snapshots[1].id, result: FIXTURE_PATH_BLOCKED },
    };
  }

  it("a compare response renders two graphs, each headed with its run's formatted date", async () => {
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
      "GET /api/path": () => ({ status: 200, body: compareBody() }),
    });
    const { container } = renderTracePage();

    await trace();

    await waitFor(() => expect(container.querySelectorAll(".pg-svg")).toHaveLength(2));
    // the composer's snapshot picker renders the same dates as <option> text
    const headings = container.querySelectorAll(".trace-group > .eyebrow");
    expect(headings).toHaveLength(2);
    expect(headings[0]).toHaveTextContent(new Date(FIXTURE_SNAPSHOTS.snapshots[0].ts_ms).toLocaleString());
    expect(headings[1]).toHaveTextContent(new Date(FIXTURE_SNAPSHOTS.snapshots[1].ts_ms).toLocaleString());
  });

  it("keeps the inspector bound to the A trace, ignoring a click in the B graph", async () => {
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
      "GET /api/path": () => ({ status: 200, body: compareBody() }),
    });
    renderTracePage();
    const user = await trace();

    // FIXTURE_PATH_SINGLE (A) has no gate-kind hop.
    const inspector = document.querySelector(".inspector") as HTMLElement;
    await waitFor(() => expect(within(inspector).queryByRole("button")).not.toBeNull());
    await expandBlock(user, inspector);
    expect(within(inspector).getByText("uid ep:host44")).toBeInTheDocument();

    // "IOT-LAN, FwRulebase, path 1" exists only on the B (FIXTURE_PATH_BLOCKED) side.
    const bStation = await screen.findByRole("button", { name: "IOT-LAN, FwRulebase, path 1" });
    await user.click(bStation);

    expect(within(inspector).getByText("uid ep:host44")).toBeInTheDocument();
  });
});

describe("TracePage: reply", () => {
  function bidirectionalBody(notes: string[] = []): BidirectionalPathResponse {
    return {
      forward: FIXTURE_PATH_SINGLE,
      reply: FIXTURE_PATH_BLOCKED,
      asymmetric: notes.length > 0,
      notes,
    };
  }

  it("off by default: a plain trace renders one pane, and reply is left off the query", async () => {
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
      "GET /api/path": () => ({ status: 200, body: FIXTURE_PATH_SINGLE }),
    });
    const { container } = renderTracePage();

    await trace();

    await waitFor(() => expect(container.querySelectorAll(".pg-svg")).toHaveLength(1));
    expect(container.querySelectorAll(".trace-group")).toHaveLength(0);
  });

  it("toggling reply on renders both a forward and a reply pane", async () => {
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
      "GET /api/path": () => ({ status: 200, body: bidirectionalBody() }),
    });
    const { container } = renderTracePage();
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: /advanced options/i }));
    await user.click(screen.getByRole("checkbox", { name: /also trace the reply/i }));
    await user.click(screen.getByRole("button", { name: /trace/i }));

    await waitFor(() => expect(container.querySelectorAll(".pg-svg")).toHaveLength(2));
    const headings = container.querySelectorAll(".trace-group > .eyebrow");
    expect(headings).toHaveLength(2);
    expect(headings[0]).toHaveTextContent("Forward");
    expect(headings[1]).toHaveTextContent("Reply");
  });

  it("shows the asymmetric-routing note above the panes when the engine names one", async () => {
    const note = "asymmetric routing: the reply's own path (r2 → r1) does not retrace r1 → r2";
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
      "GET /api/path": () => ({ status: 200, body: bidirectionalBody([note]) }),
    });
    renderTracePage();
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: /advanced options/i }));
    await user.click(screen.getByRole("checkbox", { name: /also trace the reply/i }));
    await user.click(screen.getByRole("button", { name: /trace/i }));

    expect(await screen.findByText(note)).toBeInTheDocument();
  });

  it("no asymmetric note when the reply retraces the forward path", async () => {
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
      "GET /api/path": () => ({ status: 200, body: bidirectionalBody() }),
    });
    const { container } = renderTracePage();
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: /advanced options/i }));
    await user.click(screen.getByRole("checkbox", { name: /also trace the reply/i }));
    await user.click(screen.getByRole("button", { name: /trace/i }));

    await waitFor(() => expect(container.querySelectorAll(".pg-svg")).toHaveLength(2));
    expect(container.querySelector(".banner.warn")).not.toBeInTheDocument();
  });

  it("renders one reply lane per forward leg, headed by that leg's source partition", async () => {
    const body: BidirectionalPathResponse = {
      forward: FIXTURE_PATH_SINGLE,
      reply: [
        {
          ...FIXTURE_PATH_SINGLE,
          forward_leg: 0,
          src_label: "10.0.0.0/25",
          destinations: ["10.0.0.0/25"],
          asymmetric: false,
        },
        {
          ...FIXTURE_PATH_BLOCKED,
          forward_leg: 1,
          src_label: "10.0.0.128/25",
          destinations: ["10.0.0.128/25"],
          asymmetric: true,
        },
      ],
      asymmetric: true,
      notes: [],
    };
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
      "GET /api/path": () => ({ status: 200, body }),
    });
    const { container } = renderTracePage();
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: /advanced options/i }));
    await user.click(screen.getByRole("checkbox", { name: /also trace the reply/i }));
    await user.click(screen.getByRole("button", { name: /trace/i }));

    await waitFor(() => expect(container.querySelectorAll(".pg-svg")).toHaveLength(3));
    const headings = container.querySelectorAll(".trace-group > .eyebrow");
    expect(headings).toHaveLength(3);
    expect(headings[0]).toHaveTextContent("Forward");
    expect(headings[1]).toHaveTextContent("Reply for 10.0.0.0/25");
    expect(headings[2]).toHaveTextContent("Reply for 10.0.0.128/25");
  });
});

describe("TracePage: stacked pane split", () => {
  beforeEach(installStorage);

  /** Reply on, traced, both panes rendered. The details block starts
   *  collapsed, so the only separator on the page is the one between the
   *  forward and reply panes. */
  async function traceWithReply() {
    const body: BidirectionalPathResponse = {
      forward: FIXTURE_PATH_SINGLE,
      reply: FIXTURE_PATH_BLOCKED,
      asymmetric: false,
      notes: [],
    };
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
      "GET /api/path": () => ({ status: 200, body }),
    });
    const { container } = renderTracePage();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /advanced options/i }));
    await user.click(screen.getByRole("checkbox", { name: /also trace the reply/i }));
    await user.click(screen.getByRole("button", { name: /trace/i }));
    await waitFor(() => expect(container.querySelectorAll(".trace-group")).toHaveLength(2));
    return { user, container };
  }

  function panes(container: HTMLElement): HTMLElement[] {
    return Array.from(container.querySelectorAll<HTMLElement>(".trace-group"));
  }

  function stored(): unknown {
    const raw = window.localStorage.getItem("hst.trace.panes");
    return raw === null ? undefined : JSON.parse(raw);
  }

  it("one handle between the panes, none below the last; both start at the equal split", async () => {
    const { container } = await traceWithReply();

    expect(screen.getByRole("separator", { name: "Resize Forward pane" })).toBeInTheDocument();
    expect(screen.queryByRole("separator", { name: "Resize Reply pane" })).toBeNull();
    expect(panes(container)[0].style.height).toBe("");
    expect(panes(container)[1].style.height).toBe("");
    expect(stored()).toBeUndefined();
  });

  it("ArrowDown grows the pane above the handle and persists it; the last pane stays fluid", async () => {
    const { user, container } = await traceWithReply();

    const handle = screen.getByRole("separator", { name: "Resize Forward pane" });
    handle.focus();
    await user.keyboard("{ArrowDown}");

    expect(panes(container)[0].style.height).toBe("264px");
    expect(panes(container)[1].style.height).toBe("");
    expect(stored()).toEqual({ "0": 264 });
  });

  it("ArrowUp shrinks it no further than the view's own floor", async () => {
    const { user, container } = await traceWithReply();

    const handle = screen.getByRole("separator", { name: "Resize Forward pane" });
    handle.focus();
    for (let i = 0; i < 3; i++) await user.keyboard("{ArrowUp}");

    expect(panes(container)[0].style.height).toBe("240px");
    expect(stored()).toEqual({ "0": 240 });
  });

  it("restores a persisted split", async () => {
    window.localStorage.setItem("hst.trace.panes", JSON.stringify({ 0: 300 }));
    const { container } = await traceWithReply();

    expect(panes(container)[0].style.height).toBe("300px");
    expect(panes(container)[1].style.height).toBe("");
  });

  it("double-click returns the pane to the equal split", async () => {
    window.localStorage.setItem("hst.trace.panes", JSON.stringify({ 0: 300 }));
    const { user, container } = await traceWithReply();

    await user.dblClick(screen.getByRole("separator", { name: "Resize Forward pane" }));

    expect(panes(container)[0].style.height).toBe("");
    expect(stored()).toEqual({});
  });

  it("a drag on a zero-height pane leaves the split alone", async () => {
    const { user, container } = await traceWithReply();

    const handle = screen.getByRole("separator", { name: "Resize Forward pane" });
    await user.pointer([
      { target: handle, keys: "[MouseLeft>]", coords: { clientY: 300 } },
      { target: handle, coords: { clientY: 400 } },
      { target: handle, keys: "[/MouseLeft]" },
    ]);

    expect(panes(container)[0].style.height).toBe("");
  });
});
