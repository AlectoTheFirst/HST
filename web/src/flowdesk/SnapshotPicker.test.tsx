import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { SnapshotPicker } from "./SnapshotPicker";
import { mockApi } from "../test/fetchMock";
import { FIXTURE_SNAPSHOTS } from "../test/fixtures";
import type { Snapshot, SnapshotList } from "../api/types";

// A device run whose parent is the fixture's older full cycle, and a refresh
// run whose parent is not in the list.
const SNAPSHOTS_WITH_NON_FULL_RUNS: SnapshotList = {
  ...FIXTURE_SNAPSHOTS,
  snapshots: [
    ...FIXTURE_SNAPSHOTS.snapshots,
    {
      id: "1724100000000",
      ts_ms: 1724100000000,
      created: "2026-08-19T18:40:00+00:00",
      nodes: 3701,
      rels: 33201,
      sources_fresh: ["unifi"],
      sources_carried: ["vyos"],
      sources_failed: [],
      degraded: false,
      kind: "device",
      parent: FIXTURE_SNAPSHOTS.snapshots[1].ts_ms,
    },
    {
      id: "1724050000000",
      ts_ms: 1724050000000,
      created: "2026-08-19T04:26:40+00:00",
      nodes: 3702,
      rels: 33202,
      sources_fresh: ["meraki"],
      sources_carried: ["vyos", "unifi"],
      sources_failed: [],
      degraded: false,
      kind: "refresh",
      parent: 1723000000000, // not in the list
    },
  ],
};

function optionLabel(s: Snapshot): string {
  const label = new Date(s.ts_ms).toLocaleString();
  return s.degraded ? `${label} (degraded)` : label;
}

function renderPicker(
  props: Partial<React.ComponentProps<typeof SnapshotPicker>> = {},
) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <SnapshotPicker value="" onChange={() => {}} label="snapshot" {...props} />
    </QueryClientProvider>,
  );
}

describe("SnapshotPicker", () => {
  it("renders one option per snapshot, labeled with its local date-time", async () => {
    mockApi({ "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }) });
    renderPicker();

    const select = await screen.findByRole("combobox", { name: "snapshot" });
    const fresh = FIXTURE_SNAPSHOTS.snapshots[0];
    expect(
      await within(select).findByRole("option", { name: new Date(fresh.ts_ms).toLocaleString() }),
    ).toBeInTheDocument();
    expect(within(select).getAllByRole("option")).toHaveLength(FIXTURE_SNAPSHOTS.snapshots.length);
  });

  it("shows a disabled option when the snapshots do not load", async () => {
    mockApi({ "GET /api/snapshots": () => ({ status: 500, body: { error: "store not reachable" } }) });
    renderPicker({ allowCurrent: true });

    const select = await screen.findByRole("combobox", { name: "snapshot" });
    expect(await within(select).findByRole("option", { name: "Snapshots not loaded" })).toBeDisabled();
    expect(within(select).getByRole("option", { name: "Current" })).toBeInTheDocument();
  });

  it("suffixes a degraded snapshot's label with \"(degraded)\"", async () => {
    mockApi({ "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }) });
    renderPicker();

    const degraded = FIXTURE_SNAPSHOTS.snapshots.find((s) => s.degraded)!;
    expect(await screen.findByRole("option", { name: optionLabel(degraded) })).toBeInTheDocument();
  });

  it("offers a \"current\" option valued \"\" first when allowCurrent is set", async () => {
    mockApi({ "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }) });
    renderPicker({ allowCurrent: true });

    const select = await screen.findByRole("combobox", { name: "snapshot" });
    await waitFor(() =>
      expect(within(select).getAllByRole("option")).toHaveLength(FIXTURE_SNAPSHOTS.snapshots.length + 1),
    );
    const options = within(select).getAllByRole("option") as HTMLOptionElement[];
    expect(options[0]).toHaveTextContent("Current");
    expect(options[0].value).toBe("");
  });

  it("omits the \"current\" option when allowCurrent is unset", async () => {
    mockApi({ "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }) });
    renderPicker();

    const select = await screen.findByRole("combobox", { name: "snapshot" });
    await within(select).findByRole("option", {
      name: new Date(FIXTURE_SNAPSHOTS.snapshots[0].ts_ms).toLocaleString(),
    });
    expect(within(select).queryByRole("option", { name: "Current" })).not.toBeInTheDocument();
  });

  it("calls onChange with the selected snapshot's id", async () => {
    mockApi({ "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }) });
    const onChange = vi.fn();
    renderPicker({ onChange });
    const user = userEvent.setup();

    const select = await screen.findByRole("combobox", { name: "snapshot" });
    // selectOptions requires the target <option> in the DOM
    await within(select).findByRole("option", { name: optionLabel(FIXTURE_SNAPSHOTS.snapshots[1]) });
    await user.selectOptions(select, FIXTURE_SNAPSHOTS.snapshots[1].id);

    expect(onChange).toHaveBeenCalledWith(FIXTURE_SNAPSHOTS.snapshots[1].id);
  });

  it("lists every run, each labeled with its kind and its parent", async () => {
    mockApi({ "GET /api/snapshots": () => ({ status: 200, body: SNAPSHOTS_WITH_NON_FULL_RUNS }) });
    renderPicker();

    const select = await screen.findByRole("combobox", { name: "snapshot" });
    await waitFor(() =>
      expect(within(select).getAllByRole("option")).toHaveLength(
        SNAPSHOTS_WITH_NON_FULL_RUNS.snapshots.length,
      ),
    );
    const device = SNAPSHOTS_WITH_NON_FULL_RUNS.snapshots[2];
    const parentLabel = new Date(FIXTURE_SNAPSHOTS.snapshots[1].ts_ms).toLocaleString();
    expect(
      within(select).getByRole("option", {
        name: `${new Date(device.ts_ms).toLocaleString()} [device, parent ${parentLabel}]`,
      }),
    ).toBeInTheDocument();
    // the refresh run's parent (1723000000000) is not in the list
    const refresh = SNAPSHOTS_WITH_NON_FULL_RUNS.snapshots[3];
    expect(
      within(select).getByRole("option", {
        name: `${new Date(refresh.ts_ms).toLocaleString()} [refresh, parent 1723000000000]`,
      }),
    ).toBeInTheDocument();
  });

  it("offers no control that hides runs from the list", async () => {
    mockApi({ "GET /api/snapshots": () => ({ status: 200, body: SNAPSHOTS_WITH_NON_FULL_RUNS }) });
    renderPicker();

    await screen.findByRole("combobox", { name: "snapshot" });
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
  });

  it("lists the options of a truncated list", async () => {
    mockApi({
      "GET /api/snapshots": () => ({
        status: 200,
        body: { ...FIXTURE_SNAPSHOTS, truncated: true },
      }),
    });
    renderPicker();

    const select = await screen.findByRole("combobox", { name: "snapshot" });
    await waitFor(() =>
      expect(within(select).getAllByRole("option")).toHaveLength(FIXTURE_SNAPSHOTS.snapshots.length),
    );
  });
});
