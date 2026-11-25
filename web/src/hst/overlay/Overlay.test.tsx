import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { useState } from "react";
import { FakeSource, history } from "../test/runs";
import Overlay, { factLines, type Pin } from "./Overlay";

// In `history`, port dev:s0d3/port/eth0 flips on run 6 and dev:s0d4/port/eth0 on run 8.
const UID = "dev:s0d3/port/eth0";

function Harness({
  source,
  run,
  canReadText,
  onRegression,
}: {
  source: FakeSource;
  run: number;
  canReadText: boolean;
  onRegression?: (before: number, after: number) => void;
}) {
  const [pinned, setPinned] = useState<Pin | null>(null);
  return (
    <Overlay
      source={source}
      uid={UID}
      run={source.keys[run]}
      runLabel={`run ${run}`}
      canReadText={canReadText}
      pinned={pinned}
      onPin={setPinned}
      onClose={() => {}}
      onRegression={onRegression}
    />
  );
}

describe("the interface overlay", () => {
  const source = new FakeSource(history(8));

  it("shows the interface configuration at the run", async () => {
    render(<Harness source={source} run={2} canReadText />);
    expect(await screen.findByText(/no shutdown/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Interface at run 2" })).toBeInTheDocument();
  });

  it("pins A and compares it with B side by side, the changed line marked", async () => {
    const { rerender } = render(<Harness source={source} run={2} canReadText />);
    await screen.findByText(/no shutdown/);
    fireEvent.click(screen.getByRole("button", { name: "Pin A" }));
    rerender(<Harness source={source} run={7} canReadText />);
    await screen.findByRole("heading", { name: "Interface at run 7" });
    await waitFor(() => expect(screen.getByText(/uplink shutdown$/)).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Compare with B" }));
    const table = within(screen.getByRole("table", { name: "Comparison of A and B" }));
    expect(table.getByRole("columnheader", { name: "A: run 2" })).toBeInTheDocument();
    expect(table.getByRole("columnheader", { name: "B: run 7" })).toBeInTheDocument();
    const changed = screen.getAllByRole("row").filter((r) => r.getAttribute("data-kind") === "changed");
    expect(changed.map((r) => r.textContent)).toEqual([" no shutdown shutdown"]);
  });

  it("starts a regression assessment from A to B", async () => {
    const onRegression = vi.fn();
    const { rerender } = render(<Harness source={source} run={2} canReadText onRegression={onRegression} />);
    await screen.findByText(/no shutdown/);
    fireEvent.click(screen.getByRole("button", { name: "Pin A" }));
    expect(screen.queryByRole("button", { name: "Explain this regression" })).toBeNull();
    rerender(<Harness source={source} run={7} canReadText onRegression={onRegression} />);
    await screen.findByRole("heading", { name: "Interface at run 7" });
    fireEvent.click(await screen.findByRole("button", { name: "Compare with B" }));
    fireEvent.click(screen.getByRole("button", { name: "Explain this regression" }));
    expect(onRegression).toHaveBeenCalledWith(source.keys[2], source.keys[7]);
  });

  it("compares the facts when the configuration needs a permission the user lacks", async () => {
    const spy = vi.spyOn(source, "interfaceText");
    render(<Harness source={source} run={2} canReadText={false} />);
    expect(await screen.findByText("No interfaces.read permission")).toBeInTheDocument();
    expect(spy).not.toHaveBeenCalled();
    expect(screen.getByText(/interface\.oper_status: up/)).toBeInTheDocument();
  });

  it("lists the facts one per line", () => {
    const lines = factLines({
      uid: "u",
      snapshot: 1,
      label: "Port",
      device_uid: "dev:a",
      name: "eth0",
      interface: { mtu: 1500 },
      port: null,
      contexts: ["vrf:a"],
      addresses: [],
      lags: [],
    });
    expect(lines).toEqual(["name: eth0", "device: dev:a", "interface.mtu: 1500", "contexts: vrf:a", "addresses: ", "lags: "]);
  });
});
