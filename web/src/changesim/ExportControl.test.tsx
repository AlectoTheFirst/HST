/** The tests cover the export control on the Predicted pane. */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ExportControl } from "./ExportControl";
import { mockApi } from "../test/fetchMock";
import { FIXTURE_SIMULATE_POLICY_CHANGE } from "../test/fixtures";
import type { SimulatePolicyChangeResult } from "./assessImpact";

const BANNED_WORDS = /\b(reached|delivered|reachability|live|intended)\b/i;

const SHOWN = FIXTURE_SIMULATE_POLICY_CHANGE.snapshot as string;
const ARCHIVE = { raw: "zip-bytes", headers: { "Content-Type": "application/zip" } };

let click: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  vi.stubGlobal(
    "URL",
    Object.assign(globalThis.URL, {
      createObjectURL: vi.fn(() => "blob:hst"),
      revokeObjectURL: vi.fn(),
    }),
  );
  click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function renderControl(policy: SimulatePolicyChangeResult = FIXTURE_SIMULATE_POLICY_CHANGE) {
  return render(<ExportControl policy={policy} />);
}

function exportRoute(headers: Record<string, string>, seen?: unknown[]) {
  return {
    "POST /api/changesim/export": (req: { body: unknown }) => {
      seen?.push(req.body);
      return { ...ARCHIVE, headers: { ...ARCHIVE.headers, ...headers } };
    },
  };
}

describe("ExportControl", () => {
  it("sends the depth and the sites chosen at the control", async () => {
    const seen: unknown[] = [];
    mockApi(exportRoute({ "X-HST-Snapshot": SHOWN }, seen));
    renderControl();

    expect(screen.getByLabelText("Depth")).toHaveValue(1);

    const user = userEvent.setup();
    await user.clear(screen.getByLabelText("Depth"));
    await user.type(screen.getByLabelText("Depth"), "3");
    await user.type(screen.getByLabelText("Sites"), "fra01, ber02");
    await user.click(screen.getByRole("button", { name: /Download current data/ }));

    await waitFor(() => expect(seen).toHaveLength(1));
    expect(seen[0]).toMatchObject({
      depth: 3,
      sites: ["fra01", "ber02"],
      intents: FIXTURE_SIMULATE_POLICY_CHANGE.intents,
    });
    expect(seen[0]).not.toHaveProperty("snapshot");
  });

  it("clamps a depth outside the engine's bounds once, at the click", async () => {
    const seen: unknown[] = [];
    mockApi(exportRoute({ "X-HST-Snapshot": SHOWN }, seen));
    renderControl();

    const user = userEvent.setup();
    await user.clear(screen.getByLabelText("Depth"));
    await user.type(screen.getByLabelText("Depth"), "40");
    await user.click(screen.getByRole("button", { name: /Download current data/ }));

    await waitFor(() => expect(seen).toHaveLength(1));
    expect(seen[0]).toMatchObject({ depth: 8 });
  });

  it("hands the generated file to the browser under the name the backend chose", async () => {
    mockApi(
      exportRoute({
        "X-HST-Snapshot": SHOWN,
        "Content-Disposition": 'attachment; filename="hst-change-simulation-99.zip"',
      }),
    );
    renderControl();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /Download current data/ }));
    await waitFor(() => expect(click).toHaveBeenCalled());
  });

  it("says nothing about the run when the fresh run pinned the one on screen", async () => {
    mockApi(exportRoute({ "X-HST-Snapshot": SHOWN }));
    const { container } = renderControl();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /Download current data/ }));
    await waitFor(() => expect(click).toHaveBeenCalled());
    expect(screen.queryByText(/^Export run /)).toBeNull();
    expect(container.textContent).not.toMatch(BANNED_WORDS);
  });

  it("names the run when the fresh run pinned a different one", async () => {
    mockApi(exportRoute({ "X-HST-Snapshot": "1724323200000" }));
    const { container } = renderControl();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /Download current data/ }));

    expect(await screen.findByText(/^Export run /)).toBeInTheDocument();
    expect(container.textContent).not.toMatch(BANNED_WORDS);
  });

  it("reports a refused export in a line", async () => {
    mockApi({
      "POST /api/changesim/export": () => ({
        status: 400,
        body: { error: "every flow needs a src and a dst" },
      }),
    });
    renderControl();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /Download current data/ }));

    expect(await screen.findByText("every flow needs a src and a dst")).toBeInTheDocument();
    expect(click).not.toHaveBeenCalled();
  });

  it("sends no flows when the tool derived its own", async () => {
    const seen: unknown[] = [];
    mockApi(exportRoute({ "X-HST-Snapshot": SHOWN }, seen));
    renderControl({
      ...FIXTURE_SIMULATE_POLICY_CHANGE,
      flows_derived: "no flows were supplied, so a bounded set was derived",
    });
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /Download current data/ }));

    await waitFor(() => expect(seen).toHaveLength(1));
    expect(seen[0]).not.toHaveProperty("flows");
  });
});
