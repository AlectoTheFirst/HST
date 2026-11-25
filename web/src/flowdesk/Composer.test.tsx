import { describe, it, expect, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Composer } from "./Composer";
import { mockApi } from "../test/fetchMock";
import { FIXTURE_SNAPSHOTS } from "../test/fixtures";
import type { Snapshot } from "../api/types";

/** The older run of FIXTURE_SNAPSHOTS is `degraded`. */
function optionLabel(s: Snapshot): string {
  const label = new Date(s.ts_ms).toLocaleString();
  return s.degraded ? `${label} (degraded)` : label;
}

function renderComposer() {
  const onTrace = vi.fn();
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <Composer onTrace={onTrace} tracing={false} />
    </QueryClientProvider>,
  );
  return onTrace;
}

describe("Composer start VRF", () => {
  it("shows an alert when the VRFs do not load", async () => {
    mockApi({
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
      "GET /api/path/vrfs": () => ({ status: 500, body: { error: "graph not reachable" } }),
    });
    renderComposer();

    expect(await screen.findByRole("alert")).toHaveTextContent("VRFs not loaded");
    expect(screen.queryByText("not a VRF in this run")).not.toBeInTheDocument();
  });
});

describe("Composer snapshot and compare fields", () => {
  it("submits with no snapshot params when the picker is left at current and compare is off", async () => {
    mockApi({ "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }) });
    const onTrace = renderComposer();
    const user = userEvent.setup();
    await screen.findByRole("combobox", { name: "Snapshot" });

    await user.click(screen.getByRole("button", { name: /trace/i }));

    expect(onTrace).toHaveBeenCalledWith(
      expect.objectContaining({ snapshot: undefined, compareWith: undefined }),
    );
  });

  it("includes the chosen snapshot's id when a run is picked", async () => {
    mockApi({ "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }) });
    const onTrace = renderComposer();
    const user = userEvent.setup();

    const picker = await screen.findByRole("combobox", { name: "Snapshot" });
    await within(picker).findByRole("option", {
      name: new Date(FIXTURE_SNAPSHOTS.snapshots[0].ts_ms).toLocaleString(),
    });
    await user.selectOptions(picker, FIXTURE_SNAPSHOTS.snapshots[0].id);
    await user.click(screen.getByRole("button", { name: /trace/i }));

    expect(onTrace).toHaveBeenCalledWith(
      expect.objectContaining({ snapshot: FIXTURE_SNAPSHOTS.snapshots[0].id }),
    );
  });

  it("hides the compare picker until the compare checkbox is checked, then emits its id", async () => {
    mockApi({ "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }) });
    const onTrace = renderComposer();
    const user = userEvent.setup();
    await screen.findByRole("combobox", { name: "Snapshot" });

    expect(screen.queryByRole("combobox", { name: "Compare with" })).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /advanced options/i }));
    await user.click(screen.getByRole("checkbox", { name: "Compare" }));
    const compareWith = await screen.findByRole("combobox", { name: "Compare with" });
    await within(compareWith).findByRole("option", { name: optionLabel(FIXTURE_SNAPSHOTS.snapshots[1]) });
    await user.selectOptions(compareWith, FIXTURE_SNAPSHOTS.snapshots[1].id);
    await user.click(screen.getByRole("button", { name: /trace/i }));

    expect(onTrace).toHaveBeenCalledWith(
      expect.objectContaining({ compareWith: FIXTURE_SNAPSHOTS.snapshots[1].id }),
    );
  });

  it("drops the compare value when the checkbox is unchecked again", async () => {
    mockApi({ "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }) });
    const onTrace = renderComposer();
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: /advanced options/i }));
    await user.click(screen.getByRole("checkbox", { name: "Compare" }));
    const compareWith = await screen.findByRole("combobox", { name: "Compare with" });
    await within(compareWith).findByRole("option", { name: optionLabel(FIXTURE_SNAPSHOTS.snapshots[1]) });
    await user.selectOptions(compareWith, FIXTURE_SNAPSHOTS.snapshots[1].id);
    await user.click(screen.getByRole("checkbox", { name: "Compare" }));

    expect(screen.queryByRole("combobox", { name: "Compare with" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /trace/i }));

    expect(onTrace).toHaveBeenCalledWith(expect.objectContaining({ compareWith: undefined }));
  });
});
