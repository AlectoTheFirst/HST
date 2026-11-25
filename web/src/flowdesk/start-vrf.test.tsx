import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Composer } from "./Composer";
import TracePage from "./TracePage";
import { mockApi } from "../test/fetchMock";
import { FIXTURE_PATH_SINGLE, FIXTURE_SNAPSHOTS } from "../test/fixtures";
import type { StartVrf } from "../api/types";

const GLOBAL: StartVrf = { name: "global_segment", devices: 4 };
const HOSTING: StartVrf = { name: "hosting", devices: 12 };

function client() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } });
}

function renderComposer() {
  const onTrace = vi.fn();
  render(
    <QueryClientProvider client={client()}>
      <Composer onTrace={onTrace} tracing={false} />
    </QueryClientProvider>,
  );
  return onTrace;
}

/** The request URLs the page sent to one API path, query string included. */
function requestsTo(path: string): URL[] {
  return vi
    .mocked(fetch)
    .mock.calls.map(([input]) => new URL(String(input), "http://localhost"))
    .filter((url) => url.pathname === path);
}

function mockVrfs() {
  mockApi({
    "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
    "GET /api/path/vrfs": () => ({ status: 200, body: { vrfs: [GLOBAL, HOSTING] } }),
  });
}

async function waitForVrfs() {
  await waitFor(() => expect(document.querySelectorAll("datalist option")).toHaveLength(2));
}

describe("Composer start VRF", () => {
  it("lists each VRF name of the run once, by its name only", async () => {
    mockVrfs();
    renderComposer();

    await waitForVrfs();
    const options = [...document.querySelectorAll("datalist option")];
    expect(options.map((o) => o.getAttribute("value"))).toEqual(["global_segment", "hosting"]);
    expect(options.map((o) => o.getAttribute("label"))).toEqual([null, null]);
  });

  it("sends the VRF name the field names", async () => {
    mockVrfs();
    const onTrace = renderComposer();
    const user = userEvent.setup();
    await waitForVrfs();

    await user.type(screen.getByRole("combobox", { name: "Start VRF" }), "hosting");
    await user.click(screen.getByRole("button", { name: /trace/i }));

    expect(onTrace).toHaveBeenCalledWith(expect.objectContaining({ startVrf: "hosting" }));
  });

  it("matches the VRF name case-sensitively", async () => {
    mockVrfs();
    const onTrace = renderComposer();
    const user = userEvent.setup();
    await waitForVrfs();

    const field = screen.getByRole("combobox", { name: "Start VRF" });
    await user.type(field, "Hosting");
    await user.click(screen.getByRole("button", { name: /trace/i }));

    expect(onTrace).not.toHaveBeenCalled();
    expect(field).toHaveAttribute("aria-invalid", "true");
  });

  it("sends no start VRF when the field is empty", async () => {
    mockVrfs();
    const onTrace = renderComposer();
    const user = userEvent.setup();
    await waitForVrfs();

    await user.click(screen.getByRole("button", { name: /trace/i }));

    expect(onTrace).toHaveBeenCalledWith(expect.objectContaining({ startVrf: undefined }));
  });

  it("does not trace while the field names no VRF of the run", async () => {
    mockVrfs();
    const onTrace = renderComposer();
    const user = userEvent.setup();
    await waitForVrfs();

    const field = screen.getByRole("combobox", { name: "Start VRF" });
    await user.type(field, "nowhere");
    await user.click(screen.getByRole("button", { name: /trace/i }));

    expect(onTrace).not.toHaveBeenCalled();
    expect(field).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByText("not a VRF in this run")).toBeInTheDocument();
  });

  it("reads the VRFs of the run the snapshot picker names", async () => {
    mockVrfs();
    renderComposer();
    const user = userEvent.setup();
    const run = FIXTURE_SNAPSHOTS.snapshots[0];

    const picker = await screen.findByRole("combobox", { name: "Snapshot" });
    await screen.findByRole("option", { name: new Date(run.ts_ms).toLocaleString() });
    await user.selectOptions(picker, run.id);

    await waitFor(() =>
      expect(requestsTo("/api/path/vrfs").some((url) => url.searchParams.get("snapshot") === run.id)).toBe(true),
    );
  });
});

describe("TracePage start VRF", () => {
  it("sends the start VRF to GET /api/path as start_vrf", async () => {
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
      "GET /api/path/vrfs": () => ({ status: 200, body: { vrfs: [GLOBAL, HOSTING] } }),
      "GET /api/path": () => ({ status: 200, body: FIXTURE_PATH_SINGLE }),
    });
    render(
      <QueryClientProvider client={client()}>
        <MemoryRouter>
          <TracePage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    const user = userEvent.setup();
    await waitForVrfs();

    await user.type(screen.getByRole("combobox", { name: "Start VRF" }), "hosting");
    await user.click(screen.getByRole("button", { name: /trace/i }));

    await waitFor(() => expect(requestsTo("/api/path")).toHaveLength(1));
    const sent = requestsTo("/api/path")[0].searchParams;
    expect(sent.get("start_vrf")).toBe("hosting");
    expect(sent.has("start_table")).toBe(false);
  });
});
