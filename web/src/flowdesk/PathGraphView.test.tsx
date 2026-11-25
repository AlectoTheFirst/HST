import { describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { PathGraphView } from "./PathGraphView";
import { FIXTURE_PATH_ECMP, FIXTURE_PATH_LEAF_SPINE, FIXTURE_PATH_PARTITION, FIXTURE_PATH_SINGLE } from "../test/fixtures";
import type { GraphDirection } from "./pathGraph";
import type { PathResponse } from "../api/types";
import type { Selection } from "./selection";

function Harness({
  result,
  onSelect,
  direction,
}: {
  result: PathResponse;
  onSelect?: (s: Selection | null) => void;
  direction?: GraphDirection;
}) {
  const [selection, setSelection] = useState<Selection | null>(null);
  return (
    <PathGraphView
      result={result}
      direction={direction}
      selection={selection}
      onSelect={(s) => {
        setSelection(s);
        onSelect?.(s);
      }}
      onClear={() => {
        setSelection(null);
        onSelect?.(null);
      }}
    />
  );
}

const graph = () => screen.getByRole("group", { name: "Path graph" });
const boxNamed = (re: RegExp) => within(graph()).getByRole("button", { name: re });

describe("PathGraphView", () => {
  it("draws 1 box for each device, named with its kind and paths", () => {
    render(<Harness result={FIXTURE_PATH_LEAF_SPINE} />);
    const boxes = within(graph()).getAllByRole("button");
    expect(boxes).toHaveLength(11);
    expect(boxNamed(/^border1,/)).toHaveAccessibleName("border1, Device, paths 1, 3");
    expect(boxNamed(/^acl-in,/)).toHaveAccessibleName("acl-in, FwRulebase, paths 2, 4");
  });

  it("badges a box with more than 1 outgoing link", () => {
    render(<Harness result={FIXTURE_PATH_ECMP} />);
    expect(boxNamed(/^core1,/).textContent).toContain("ECMP 2");
    expect(boxNamed(/^eth0\.10,/).textContent).not.toContain("ECMP");
  });

  it("is 1 tab stop", () => {
    render(<Harness result={FIXTURE_PATH_LEAF_SPINE} />);
    const stops = within(graph())
      .getAllByRole("button")
      .filter((b) => b.getAttribute("tabindex") === "0");
    expect(stops).toHaveLength(1);
  });

  it("selects the hop of a clicked box and fades the boxes off its paths", async () => {
    const onSelect = vi.fn();
    const user = userEvent.setup();
    render(<Harness result={FIXTURE_PATH_LEAF_SPINE} onSelect={onSelect} />);
    await user.click(boxNamed(/^border2,/));
    expect(onSelect).toHaveBeenLastCalledWith({ type: "hop", data: expect.objectContaining({ uid: "dev:border2" }) });
    expect(graph().classList).toContain("faded");
    expect(boxNamed(/^border2,/)).toHaveAttribute("aria-pressed", "true");
    expect(boxNamed(/^border2,/).classList).toContain("near");
    expect(boxNamed(/^spine1,/).classList).toContain("near");
    expect(boxNamed(/^border1,/).classList).not.toContain("near");
    // a second click clears
    await user.click(boxNamed(/^border2,/));
    expect(onSelect).toHaveBeenLastCalledWith(null);
    expect(graph().classList).not.toContain("faded");
  });

  it("names the interfaces on the links of the selected path only", async () => {
    const user = userEvent.setup();
    const { container } = render(<Harness result={FIXTURE_PATH_LEAF_SPINE} />);
    expect(container.querySelectorAll(".pg-linklabel")).toHaveLength(0);
    await user.click(screen.getByRole("button", { name: /^Path 3/ }));
    const labels = [...container.querySelectorAll(".pg-linklabel")].map((t) => t.textContent);
    expect(labels).toContain("eth50 > eth1");
    expect(labels).toContain("eth3 > eth2");
    expect(labels).not.toContain("eth49 > eth1");
  });

  it("lists each path with its first devices and its verdict", () => {
    render(<Harness result={FIXTURE_PATH_LEAF_SPINE} />);
    const paths = within(screen.getByRole("group", { name: "Paths" })).getAllByRole("button");
    expect(paths.map((p) => p.textContent)).toEqual([
      "Path 1via spine1, border1forwarded",
      "Path 2via spine1, border2blocked by acl-in rule 40",
      "Path 3via spine2, border1forwarded",
      "Path 4via spine2, border2blocked by acl-in rule 40",
    ]);
    expect(paths[1].querySelector(".pg-pill.bad")).not.toBeNull();
  });

  it("dashes the links only blocked paths use", () => {
    const { container } = render(<Harness result={FIXTURE_PATH_LEAF_SPINE} />);
    const blocked = [...container.querySelectorAll(".pg-link.blocked title")].map((t) => t.textContent);
    expect(blocked.sort()).toEqual(["border2 to acl-in, paths 2, 4", "spine1 to border2, path 2", "spine2 to border2, path 4"]);
  });

  it("follows the links with Down and Up, moves in a step with Right and Left, selects with Enter, clears with Esc", async () => {
    const onSelect = vi.fn();
    const user = userEvent.setup();
    render(<Harness result={FIXTURE_PATH_LEAF_SPINE} onSelect={onSelect} />);
    boxNamed(/^10\.20\.1\.15,/).focus();
    await user.keyboard("{ArrowDown}");
    expect(boxNamed(/^leaf1,/)).toHaveFocus();
    await user.keyboard("{ArrowDown}");
    expect(document.activeElement?.getAttribute("aria-label")).toMatch(/^spine/);
    const first = document.activeElement?.getAttribute("aria-label");
    await user.keyboard(first?.startsWith("spine1") ? "{ArrowRight}" : "{ArrowLeft}");
    expect(document.activeElement?.getAttribute("aria-label")).not.toBe(first);
    await user.keyboard("{ArrowUp}");
    expect(boxNamed(/^leaf1,/)).toHaveFocus();
    expect(boxNamed(/^leaf1,/)).toHaveAttribute("tabindex", "0");
    await user.keyboard("{Enter}");
    expect(onSelect).toHaveBeenLastCalledWith({ type: "hop", data: expect.objectContaining({ uid: "dev:leaf1" }) });
    await user.keyboard("{Escape}");
    expect(onSelect).toHaveBeenLastCalledWith(null);
  });

  it("follows the links with Right and Left in the Left to right direction", async () => {
    const user = userEvent.setup();
    render(<Harness result={FIXTURE_PATH_LEAF_SPINE} direction="lr" />);
    boxNamed(/^10\.20\.1\.15,/).focus();
    await user.keyboard("{ArrowRight}");
    expect(boxNamed(/^leaf1,/)).toHaveFocus();
    await user.keyboard("{ArrowLeft}");
    expect(boxNamed(/^10\.20\.1\.15,/)).toHaveFocus();
  });

  it("names the source of each path when the sources differ, and shows no ECMP badge on that split", () => {
    render(<Harness result={FIXTURE_PATH_PARTITION} />);
    const paths = within(screen.getByRole("group", { name: "Paths" })).getAllByRole("button");
    expect(paths[0].textContent).toContain("192.168.10.43/32, 192.168.10.44/31");
    expect(paths[0].textContent).toContain("via table100");
    expect(boxNamed(/^core1,/).textContent).not.toContain("ECMP");
  });

  it("states delivered under the destination and the walk's word on the path pill", () => {
    const { container } = render(<Harness result={FIXTURE_PATH_LEAF_SPINE} />);
    expect(boxNamed(/^10\.40\.2\.20,/).querySelector(".pg-end.ok")?.textContent).toBe("delivered");
    expect(container.textContent).not.toMatch(/same as/i);
  });

  it("keeps every hop as a box in All hops mode", () => {
    render(<PathGraphView result={FIXTURE_PATH_SINGLE} selection={null} onSelect={() => {}} detail="all" />);
    expect(within(graph()).getAllByRole("button")).toHaveLength(FIXTURE_PATH_SINGLE.hops.length);
  });

  it("states the walk's detail when there is nothing to draw", () => {
    render(<PathGraphView result={{ ...FIXTURE_PATH_SINGLE, hops: [] }} selection={null} onSelect={() => {}} />);
    expect(screen.getByText(FIXTURE_PATH_SINGLE.detail)).toBeInTheDocument();
  });
});
