import { describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import type { Hop } from "../../api/types";
import type { Step } from "./place";
import Steps from "./Steps";

function hop(uid: string, label: string, rank: number): Hop {
  return { uid, kind: "Device", label, note: "", rank, lane: 0, shared: true };
}

describe("the step list", () => {
  it("numbers the hops A, 1, B, flies to a hop on click and lists the off-map hops", () => {
    const steps: Step[] = [
      { hop: hop("dev:a", "a", 0), uid: "dev:a", device: "dev:a", u: 1, v: 1, blocked: false },
      { hop: hop("dev:b", "b", 1), uid: "dev:b", device: "dev:b", u: 2, v: 2, blocked: true },
      { hop: hop("dev:c", "c", 2), uid: "dev:c", device: "dev:c", u: 3, v: 3, blocked: false },
    ];
    const flown: string[] = [];
    let closed = 0;
    render(<Steps steps={steps} offMap={[hop("ep:x", "x", 3)]} detail="blocked on b" onStep={(s) => flown.push(s.uid)} onClose={() => closed++} />);
    const list = screen.getByRole("complementary", { name: "Directions" });
    expect(list.querySelectorAll("li").length).toBe(3);
    expect(list.querySelectorAll(".hst-step-n")[0].textContent).toBe("A");
    expect(list.querySelectorAll(".hst-step-n")[1].textContent).toBe("1");
    expect(list.querySelectorAll(".hst-step-n")[2].textContent).toBe("B");
    expect(list.querySelector("li.hst-step-blocked")?.textContent).toContain("b");
    fireEvent.click(screen.getByRole("button", { name: /^1b/ }));
    expect(flown).toEqual(["dev:b"]);
    expect(screen.getByText(/Not on the map: x/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(closed).toBe(1);
  });

  it("offers a lane picker for a trace of 2 lanes or more", () => {
    const steps: Step[] = [{ hop: hop("dev:a", "a", 0), uid: "dev:a", device: "dev:a", u: 1, v: 1, blocked: false }];
    const picked: number[] = [];
    render(
      <Steps steps={steps} offMap={[]} detail="2 paths" onStep={() => {}} onClose={() => {}} lanes={[0, 1, 2]} lane={0} onLane={(l) => picked.push(l)} />,
    );
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "2" } });
    expect(picked).toEqual([2]);
  });

  it("offers no lane picker for a trace of one lane", () => {
    const steps: Step[] = [{ hop: hop("dev:a", "a", 0), uid: "dev:a", device: "dev:a", u: 1, v: 1, blocked: false }];
    render(<Steps steps={steps} offMap={[]} detail="forwarded" onStep={() => {}} onClose={() => {}} />);
    expect(screen.queryByRole("combobox")).toBeNull();
    expect(screen.queryByText(/not drawn/)).toBeNull();
  });

  it("prints the walk's word on the step that ends a leg that is not forwarded or not decided", () => {
    const steps: Step[] = [
      { hop: hop("dev:a", "a", 0), uid: "dev:a", device: "dev:a", u: 1, v: 1, blocked: false },
      { hop: hop("dev:b", "b", 1), uid: "dev:b", device: "dev:b", u: 2, v: 2, blocked: true, word: "no route found" },
    ];
    render(<Steps steps={steps} offMap={[]} detail="no route" onStep={() => {}} onClose={() => {}} />);
    const words = document.querySelectorAll(".hst-step-word");
    expect(words).toHaveLength(1);
    expect(words[0].textContent).toBe("no route found");
  });
});
