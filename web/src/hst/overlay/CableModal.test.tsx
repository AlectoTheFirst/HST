import { describe, expect, it } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { FakeSource, history } from "../test/runs";
import CableModal, { type Cable } from "./CableModal";

// In `history`, port dev:s0d3/port/eth0 flips on run 6.
const A = "dev:s0d3/port/eth0";
const B = "dev:s0d4/port/eth0";

function cable(id: string, a: string, b: string): Cable {
  return {
    id,
    a: { port: a, device: a.split("/")[0], name: a.split("/").pop()! },
    b: { port: b, device: b.split("/")[0], name: b.split("/").pop()! },
    row: { cable_id: id, a_port: a, b_port: b },
  };
}

describe("the cable modal", () => {
  const source = new FakeSource(history(8));

  it("shows the A side and B side configuration side by side and marks the lines changed since the previous run", async () => {
    render(
      <CableModal source={source} cables={[cable("c1", A, B)]} run={source.keys[6]} previous={source.keys[5]} canReadText x={40} y={40} onClose={() => {}} />,
    );
    const a = await screen.findByLabelText("A side");
    const b = screen.getByLabelText("B side");
    expect(within(a).getByText(/interface eth0/)).toBeTruthy();
    expect(within(b).getByText(/interface eth0/)).toBeTruthy();
    await waitFor(() => expect(a.querySelectorAll("[data-changed]").length).toBe(1));
    expect(a.querySelector("[data-changed]")?.textContent).toMatch(/shutdown/);
    expect(b.querySelectorAll("[data-changed]").length).toBe(0);
  });

  it("shows the interface facts without interfaces.read", async () => {
    const before = source.calls.length;
    render(<CableModal source={source} cables={[cable("c1", A, B)]} run={source.keys[6]} previous={source.keys[5]} canReadText={false} x={0} y={0} onClose={() => {}} />);
    const a = await screen.findByLabelText("A side");
    expect(within(a).getByText(/^name: eth0/)).toBeTruthy();
    expect(within(a).getByText(/interfaces.read/)).toBeTruthy();
    expect(source.calls.slice(before).filter((c) => c.startsWith("interface-text"))).toEqual([]);
  });

  it("switches between the cables of one device pair", async () => {
    const C = "dev:s0d3/port/eth1";
    const D = "dev:s0d4/port/eth1";
    render(
      <CableModal source={source} cables={[cable("c1", A, B), cable("c2", C, D)]} run={source.keys[6]} previous={null} canReadText x={0} y={0} onClose={() => {}} />,
    );
    await screen.findByLabelText("A side");
    fireEvent.click(screen.getByRole("tab", { name: "eth1 to eth1" }));
    await waitFor(() => expect(within(screen.getByLabelText("A side")).getByText(/interface eth1/)).toBeTruthy());
    expect(screen.getByLabelText("A side").querySelectorAll("[data-changed]").length).toBe(0);
  });
});
