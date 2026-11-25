import { describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { FakeSource, history } from "../test/runs";
import SegmentModal from "./SegmentModal";

describe("the segment modal", () => {
  it("lists the clients of a segment with name, IP, MAC and port", async () => {
    const states = history(2);
    const uid = "dev:s0d1/segment/bd:vlan:fab0:10";
    for (const t of states) {
      t.render_t2_segments.push({ uid, device_uid: "dev:s0d1", tile: "block:s0:campus", vid: 10, name: "users", prefix: "10.1.10.0/24", client_count: 2 });
    }
    const source = new FakeSource(states);
    const run = source.keys[0];
    source.clients.set(uid, [
      { uid: "ep:1", name: "pc-1", ip: ["10.1.10.5"], mac: "aa:bb", port: "eth3", last_seen_ts: 1 },
      { uid: "ep:2", name: null, ip: [], mac: "cc:dd", port: null, last_seen_ts: null },
    ]);
    let closed = 0;
    render(<SegmentModal source={source} uid={uid} run={run} device="s0d1" onClose={() => closed++} />);
    const modal = await screen.findByRole("region", { name: "Segment clients" });
    expect(await screen.findByText("pc-1")).toBeTruthy();
    expect(screen.getByText("10.1.10.5")).toBeTruthy();
    expect(screen.getByText("cc:dd")).toBeTruthy();
    expect(screen.getByText("unknown")).toBeTruthy();
    expect(modal.querySelector("h3")?.textContent).toContain("10.1.10.0/24");
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(closed).toBe(1);
  });

  it("shows the error of a segment the source does not know", async () => {
    const source = new FakeSource(history(2));
    render(<SegmentModal source={source} uid="dev:x/segment/none" run={source.keys[0]} device="x" onClose={() => {}} />);
    expect((await screen.findByRole("alert")).textContent).toContain("unknown segment");
  });
});
